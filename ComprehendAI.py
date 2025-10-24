"""
ComprehendAI - IDA Pro AI 分析插件
基于 OpenAI API 的智能逆向工程分析工具
"""
import traceback
import idaapi
import idc
import idautils
import ida_xref
import json
import os
from typing import Optional, Set, List

from idaapi import action_handler_t, UI_Hooks
from threading import Lock, Thread, Event
from openai import OpenAI
from enum import Enum


class TaskType(Enum):
    """任务类型枚举"""
    ANALYSIS = 1
    CUSTOM_QUERY = 2
    CUSTOM_QUERY_WITH_CODE = 3


class QueryStatus(Enum):
    """查询状态枚举"""
    SUCCESS = 1
    FAILED = 2
    STOPPED = 3

# 配置文件名称常量
CONFIG_FILENAME = 'config.json'
DEFAULT_MAX_DEPTH = 2
DEFAULT_ANALYSIS_DEPTH = 2


class ConfigManager:
    """
    配置管理器 - 单例模式
    负责加载配置文件和创建 OpenAI 客户端
    """
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        with cls._lock:
            if not cls._instance:
                cls._instance = super().__new__(cls)
                cls._instance._initialize()
            return cls._instance
    
    def _initialize(self):
        """初始化配置管理器"""
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_path = os.path.join(self.script_dir, CONFIG_FILENAME)
        self.config = self._load_config()
        self.openai_client = self._create_openai_client()
        
    def _load_config(self) -> dict:
        """
        加载配置文件
        
        Returns:
            dict: 配置字典
            
        Raises:
            RuntimeError: 配置文件加载失败
        """
        try:
            if not os.path.exists(self.config_path):
                raise FileNotFoundError(
                    f"配置文件不存在: {self.config_path}\n"
                    f"请参考 config_sample.json 创建 config.json"
                )
            
            with open(self.config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
                
            # 验证必要的配置项
            if "openai" not in config:
                raise KeyError("配置文件缺少 'openai' 配置项")
            
            required_keys = ["api_key", "base_url", "model"]
            for key in required_keys:
                if key not in config["openai"]:
                    raise KeyError(f"配置文件缺少 'openai.{key}' 配置项")
                    
            return config
            
        except FileNotFoundError as e:
            raise RuntimeError(str(e))
        except json.JSONDecodeError as e:
            raise RuntimeError(f"配置文件 JSON 格式错误: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"加载配置文件失败: {str(e)}")
    
    def _create_openai_client(self) -> OpenAI:
        """
        创建 OpenAI 客户端
        
        Returns:
            OpenAI: OpenAI 客户端实例
        """
        return OpenAI(
            api_key=self.config["openai"]["api_key"],
            base_url=self.config["openai"]["base_url"]
        )
    
    @property
    def model_name(self) -> str:
        """获取模型名称"""
        return self.config["openai"]["model"]
    
    @property
    def client(self) -> OpenAI:
        """获取 OpenAI 客户端"""
        return self.openai_client
class DisassemblyProcessor:
    """
    反汇编代码提取处理器
    负责提取当前函数及其调用的子函数的反编译代码
    """
    
    def __init__(self, max_depth: int = DEFAULT_MAX_DEPTH):
        """
        初始化反汇编处理器
        
        Args:
            max_depth: 最大分析深度,控制递归提取子函数的层数
        """
        self.max_depth = max_depth
        self._lock = Lock()
        self._reset_state()
        
    def _reset_state(self):
        """重置处理状态"""
        with self._lock:
            self.processed_funcs: Set[int] = set()
            self.func_disasm_list: List[str] = []
    
    def get_current_function_disasm(self) -> str:
        """
        获取当前光标位置函数的反编译代码及其子函数
        
        Returns:
            str: 反编译代码字符串
            
        Raises:
            ValueError: 无法定位函数起始地址
        """
        self._reset_state()
        
        current_ea = idc.get_screen_ea()
        func_start = idc.get_func_attr(current_ea, idc.FUNCATTR_START)
        
        if func_start == idaapi.BADADDR:
            raise ValueError("无法定位函数起始地址,请确保光标位于有效函数内")
            
        self._process_function(func_start, self.max_depth)
        
        if not self.func_disasm_list:
            raise ValueError("未能提取到任何反编译代码")
            
        return "\n\n" + "=" * 80 + "\n\n".join(self.func_disasm_list)
    
    def _process_function(self, func_ea: int, depth: int):
        """
        递归处理函数及其调用的子函数
        
        Args:
            func_ea: 函数地址
            depth: 当前剩余递归深度
        """
        if func_ea in self.processed_funcs or depth < 0:
            return
            
        with self._lock:
            self.processed_funcs.add(func_ea)
        
        try:
            # 尝试反编译函数
            decompiled = str(idaapi.decompile(func_ea))
            func_name = idc.get_func_name(func_ea)
            
            # 添加函数标识信息
            header = f"\n{'=' * 80}\n函数: {func_name} (地址: {hex(func_ea)})\n{'=' * 80}\n"
            
            with self._lock:
                self.func_disasm_list.append(header + decompiled)
                
        except Exception as e:
            print(f"❌ 反编译失败 {hex(func_ea)}: {str(e)}")
            return
        
        # 递归处理子函数
        if depth > 0:
            for callee in self._get_callees(func_ea):
                self._process_function(callee, depth - 1)
    
    def _get_callees(self, func_ea: int) -> Set[int]:
        """
        获取函数调用的所有子函数地址
        
        Args:
            func_ea: 函数地址
            
        Returns:
            Set[int]: 子函数地址集合
        """
        callees = set()
        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        
        if func_end == idaapi.BADADDR:
            return callees
            
        for ea in range(func_ea, func_end):
            for xref in idautils.XrefsFrom(ea):
                # 只处理函数调用类型的交叉引用
                if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                    callee_ea = xref.to
                    # 确认是函数起始地址
                    if idc.get_func_attr(callee_ea, idc.FUNCATTR_START) == callee_ea:
                        callees.add(callee_ea)
        return callees
class AIService:
    """
    AI 服务类
    负责与 OpenAI API 交互,处理分析请求
    """
    
    def __init__(self):
        """初始化 AI 服务"""
        self.config = ConfigManager()
        self.stop_event = Event()

    def ask_ai(self, prompt: str, ai_isRunning: Lock):
        """
        向 AI 提出问题
        
        Args:
            prompt: 提示词
            ai_isRunning: 运行状态锁
        """
        messages = [{"role": "user", "content": prompt}]
        print("\n" + "=" * 80)
        print("ComprehendAI 输出:")
        print("=" * 80 + "\n")
        
        self.stop_event.clear()  # 初始化停止事件
        
        try:
            result = self._request_openai(messages)
        finally:
            # 确保无论成功失败都释放锁
            ai_isRunning.release()

        # 输出最终状态
        match result:
            case QueryStatus.SUCCESS:
                print("\n" + "=" * 80)
                print("✅ 分析完成！")
                print("=" * 80)
            case QueryStatus.FAILED:
                print("\n" + "=" * 80)
                print("❌ 分析失败，请检查配置或网络连接")
                print("=" * 80)
            case QueryStatus.STOPPED:
                print("\n" + "=" * 80)
                print("⏸️ 分析已停止")
                print("=" * 80)

    def _request_openai(self, messages: List[dict]) -> QueryStatus:
        """
        请求 OpenAI API
        
        Args:
            messages: 消息列表
            
        Returns:
            QueryStatus: 查询状态
        """
        reasoning_content = ""
        answer_content = ""
        is_answering = False
        
        try:
            completion = self.config.client.chat.completions.create(
                model=self.config.model_name,
                messages=messages,
                stream=True,
            )
            
            for chunk in completion:
                # 检查是否需要停止
                if self.stop_event.is_set():
                    print("\n\n🛑 收到停止信号,正在中断...")
                    return QueryStatus.STOPPED

                # 处理 usage 信息
                if not chunk.choices:
                    if hasattr(chunk, 'usage') and chunk.usage:
                        print(f"\n\n📊 Token 使用情况: {chunk.usage}")
                    continue
                
                delta = chunk.choices[0].delta
                
                # 处理推理内容(如果模型支持)
                if hasattr(delta, 'reasoning_content') and delta.reasoning_content:
                    print(delta.reasoning_content, end='', flush=True)
                    reasoning_content += delta.reasoning_content
                
                # 处理回复内容
                elif delta.content is not None:
                    if not is_answering and delta.content:
                        print("\n" + "=" * 20 + " 完整回复 " + "=" * 20 + "\n")
                        is_answering = True
                    answer_content += delta.content
            
            # 打印完整回复
            if answer_content:
                print(answer_content)
            else:
                print("⚠️ AI 未返回有效内容")
                
            return QueryStatus.SUCCESS
        
        except StopIteration as e:
            print(f"\n⚠️ 迭代被中断: {e}")
            return QueryStatus.STOPPED

        except Exception as e:
            print(f"\n❌ 发生错误: {e}")
            if hasattr(e, '__class__'):
                print(f"错误类型: {e.__class__.__name__}")
            traceback.print_exc()
            return QueryStatus.FAILED


# 默认分析提示词模板
DEFAULT_ANALYSIS_PROMPT = """
你是一名人工智能逆向工程专家。
我会提供你一些反汇编代码，其中首个函数是你需要分析并总结成报告的函数，
其余函数是该函数调用的一些子函数。

分析要求：
1. 重点描述主函数功能，并对核心行为进行推测
2. 简要描述子函数功能
3. 识别潜在的安全问题或漏洞
4. 分析函数的复杂度和性能特点

输出要求：
主函数功能：...
核心行为推测：...
子函数功能：...
安全性分析：...
复杂度评估：...

请使用纯文本格式输出。

下面是你要分析的反汇编代码：
"""


class AnalysisHandler:
    """
    分析处理器
    负责协调反汇编提取和 AI 分析
    """

    def __init__(self):
        """初始化分析处理器"""
        self.disassembler = DisassemblyProcessor()
        self.ai_service = AIService()
        self.ai_isRunning = Lock()
        self.prompt = DEFAULT_ANALYSIS_PROMPT
        
    def set_analysis_depth(self, depth: int):
        """
        设置分析深度
        
        Args:
            depth: 分析深度(子函数递归层数)
        """
        if depth < 0:
            print("❌ 分析深度必须大于等于 0")
            return
            
        self.disassembler.max_depth = depth
        print(f"✅ 分析深度已设置为: {depth}")
    
    def _create_analysis_prompt(self, disassembly: str) -> str:
        """
        创建分析提示词
        
        Args:
            disassembly: 反汇编代码
            
        Returns:
            str: 完整提示词
        """
        return self.prompt + "\n" + disassembly
    
    def _create_custom_query_with_code(self, disassembly: str, question: str) -> str:
        """
        创建带代码的自定义查询
        
        Args:
            disassembly: 反汇编代码
            question: 用户问题
            
        Returns:
            str: 完整提示词
        """
        return f"{question}\n\n反汇编代码:\n{disassembly}"
    
    def create_ai_task(self, task_type: TaskType, question: str = ""):
        """
        创建 AI 分析任务
        
        Args:
            task_type: 任务类型
            question: 用户问题(仅部分任务类型需要)
        """
        try:
            match task_type:
                case TaskType.ANALYSIS:
                    print("📝 正在提取反汇编代码...")
                    disassembly = self.disassembler.get_current_function_disasm()
                    prompt = self._create_analysis_prompt(disassembly)
                    self._async_task(prompt)
                    
                case TaskType.CUSTOM_QUERY:
                    if not question:
                        print("❌ 请提供问题内容")
                        return
                    self._async_task(question)
                    
                case TaskType.CUSTOM_QUERY_WITH_CODE:
                    if not question:
                        print("❌ 请提供问题内容")
                        return
                    print("📝 正在提取反汇编代码...")
                    disassembly = self.disassembler.get_current_function_disasm()
                    prompt = self._create_custom_query_with_code(disassembly, question)
                    self._async_task(prompt)
                    
        except ValueError as e:
            print(f"❌ {str(e)}")
        except Exception as e:
            print(f"❌ 创建任务失败: {str(e)}")
            traceback.print_exc()
        
    def _async_task(self, prompt: str):
        """
        异步执行 AI 任务
        
        Args:
            prompt: 提示词
        """
        if self.ai_isRunning.acquire(blocking=False):
            # 在新线程中执行 AI 请求
            task = Thread(
                target=self.ai_service.ask_ai,
                args=(prompt, self.ai_isRunning),
                daemon=True  # 设置为守护线程
            )
            task.start()
            print("🚀 AI 任务已启动...")
        else:
            print("❌ 当前 AI 正在处理任务,请稍后尝试或使用 Stop 停止当前任务")
    
    def stop(self):
        """停止当前 AI 任务"""
        if self.ai_service.stop_event.is_set():
            print("ℹ️ 没有正在运行的任务")
        else:
            self.ai_service.stop_event.set()
            print("🛑 正在停止任务...")

class ComprehendAIPlugin(idaapi.plugin_t):
    """
    ComprehendAI IDA Pro 插件
    提供基于 AI 的智能二进制代码分析功能
    """
    
    flags = idaapi.PLUGIN_HIDE
    comment = "AI-based Reverse Analysis Plugin"
    help = "Perform AI-based analysis on binary code using OpenAI"
    wanted_name = "ComprehendAI"
    wanted_hotkey = "Ctrl+Shift+A"

    # 插件动作定义 (action_id, 显示名称, 提示信息)
    ACTION_DEFINITIONS = [
        ("AI_analysis:Analysis", "🤖 AI 分析", "执行 AI 智能分析"),
        ("AI_analysis:SetDepth", "⚙️ 设置分析深度", "设置函数分析的递归深度"),
        ("AI_analysis:SetPrompt", "📝 自定义提示词", "自定义分析提示词模板"),
        ("AI_analysis:CustomQueryWithCode", "💬 带代码提问", "结合当前代码向 AI 提问"),
        ("AI_analysis:CustomQuery", "💭 直接提问", "直接向 AI 提问"),
        ("AI_analysis:Stop", "🛑 停止", "停止当前 AI 任务"),
    ]

    def init(self):
        """
        初始化插件
        
        Returns:
            int: PLUGIN_KEEP 保持插件加载
        """
        try:
            # 注册 UI 钩子
            self.ui_hook = self.MenuHook()
            self.ui_hook.hook()
            
            # 创建分析处理器
            self.handler = AnalysisHandler()
            
            # 注册所有动作
            self._register_actions()
            
            print("=" * 80)
            print("✅ ComprehendAI 插件已成功加载")
            print("=" * 80)
            return idaapi.PLUGIN_KEEP
            
        except Exception as e:
            print("=" * 80)
            print(f"❌ ComprehendAI 插件初始化失败: {str(e)}")
            print("=" * 80)
            traceback.print_exc()
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        """
        运行插件(当前未使用)
        
        Args:
            arg: 插件参数
        """
        pass

    def term(self):
        """卸载插件"""
        try:
            self.ui_hook.unhook()
            self._unregister_actions()
            print("=" * 80)
            print("👋 ComprehendAI 插件已卸载")
            print("=" * 80)
        except Exception as e:
            print(f"❌ 插件卸载时发生错误: {str(e)}")

    def _register_actions(self):
        """注册所有菜单动作"""
        for action_id, label, tooltip in self.ACTION_DEFINITIONS:
            action_desc = idaapi.action_desc_t(
                action_id,
                label,
                self.MenuCommandHandler(action_id, self.handler),
                None,
                tooltip,
                0
            )
            if not idaapi.register_action(action_desc):
                print(f"⚠️ 注册动作失败: {action_id}")

    def _unregister_actions(self):
        """注销所有菜单动作"""
        for action_id, _, _ in self.ACTION_DEFINITIONS:
            idaapi.unregister_action(action_id)

    class MenuHook(UI_Hooks):
        """菜单钩子,用于在右键菜单中添加插件选项"""
        
        def finish_populating_widget_popup(self, form, popup):
            """
            在窗口弹出菜单完成填充时调用
            
            Args:
                form: 窗口句柄
                popup: 弹出菜单句柄
            """
            widget_type = idaapi.get_widget_type(form)
            
            # 只在反汇编视图和伪代码视图中显示菜单
            if widget_type in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE):
                for action_id, _, _ in ComprehendAIPlugin.ACTION_DEFINITIONS:
                    idaapi.attach_action_to_popup(
                        form, 
                        popup, 
                        action_id, 
                        "ComprehendAI/", 
                        idaapi.SETMENU_APP
                    )

    class MenuCommandHandler(action_handler_t):
        """菜单命令处理器"""
        
        def __init__(self, action_id: str, handler: AnalysisHandler):
            """
            初始化命令处理器
            
            Args:
                action_id: 动作 ID
                handler: 分析处理器
            """
            super().__init__()
            self.action_id = action_id
            self.handler = handler
    
        def activate(self, ctx):
            """
            激活动作
            
            Args:
                ctx: 上下文
                
            Returns:
                int: 1 表示成功
            """
            try:
                match self.action_id:
                    case "AI_analysis:Analysis":
                        self.handler.create_ai_task(TaskType.ANALYSIS)
                        
                    case "AI_analysis:CustomQuery":
                        question = idaapi.ask_text(0, "", "请输入您的问题:")
                        if question:
                            self.handler.create_ai_task(TaskType.CUSTOM_QUERY, question)
                            
                    case "AI_analysis:SetDepth":
                        current_depth = self.handler.disassembler.max_depth
                        new_depth = idaapi.ask_long(
                            current_depth, 
                            f"设置分析深度 (当前: {current_depth}):"
                        )
                        if new_depth is not None:
                            self.handler.set_analysis_depth(new_depth)
                            
                    case "AI_analysis:SetPrompt":
                        new_prompt = idaapi.ask_text(
                            0, 
                            self.handler.prompt, 
                            "自定义提示词模板:"
                        )
                        if new_prompt:
                            self.handler.prompt = new_prompt
                            print("✅ 提示词模板已更新")
                            
                    case "AI_analysis:CustomQueryWithCode":
                        question = idaapi.ask_text(
                            0, 
                            "", 
                            "请输入您的问题 (将结合当前代码):"
                        )
                        if question:
                            self.handler.create_ai_task(
                                TaskType.CUSTOM_QUERY_WITH_CODE, 
                                question
                            )
                            
                    case "AI_analysis:Stop":
                        self.handler.stop()
                        
            except Exception as e:
                print(f"❌ 执行操作失败: {str(e)}")
                traceback.print_exc()
                
            return 1

        def update(self, ctx):
            """
            更新动作状态
            
            Args:
                ctx: 上下文
                
            Returns:
                int: 动作状态
            """
            return idaapi.AST_ENABLE_ALWAYS


def PLUGIN_ENTRY():
    """
    IDA Pro 插件入口点
    
    Returns:
        ComprehendAIPlugin: 插件实例
    """
    return ComprehendAIPlugin()