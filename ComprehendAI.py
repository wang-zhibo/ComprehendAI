"""
ComprehendAI - IDA Pro AI 分析插件
基于 OpenAI API 的智能逆向工程分析工具
"""
import traceback
import idaapi
import idc
import idautils
import ida_xref
import ida_bytes
import ida_nalt
import json
import os
import hashlib
import time
from datetime import datetime
from typing import Optional, Set, List, Dict, Tuple
from pathlib import Path

from idaapi import action_handler_t, UI_Hooks
from threading import Lock, Thread, Event
from openai import OpenAI
from enum import Enum


class TaskType(Enum):
    """任务类型枚举"""
    ANALYSIS = 1
    CUSTOM_QUERY = 2
    CUSTOM_QUERY_WITH_CODE = 3
    BATCH_ANALYSIS = 4  # 批量分析
    SECURITY_AUDIT = 5  # 安全审计
    VULNERABILITY_SCAN = 6  # 漏洞扫描


class QueryStatus(Enum):
    """查询状态枚举"""
    SUCCESS = 1
    FAILED = 2
    STOPPED = 3


# 配置文件名称常量
CONFIG_FILENAME = 'config.json'
DEFAULT_MAX_DEPTH = 2
DEFAULT_ANALYSIS_DEPTH = 2
CACHE_DIR = 'comprehendai_cache'
EXPORT_DIR = 'comprehendai_exports'
MAX_CACHE_SIZE = 100  # 最大缓存条目数


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


class CacheManager:
    """
    分析结果缓存管理器
    使用函数地址和代码的哈希值作为缓存键
    """
    
    def __init__(self):
        """初始化缓存管理器"""
        self.cache: Dict[str, Dict] = {}
        self._lock = Lock()
        self.cache_dir = self._get_cache_dir()
        self._load_cache()
    
    def _get_cache_dir(self) -> Path:
        """获取缓存目录路径"""
        script_dir = Path(__file__).parent
        cache_dir = script_dir / CACHE_DIR
        cache_dir.mkdir(exist_ok=True)
        return cache_dir
    
    def _generate_cache_key(self, func_ea: int, code: str) -> str:
        """
        生成缓存键
        
        Args:
            func_ea: 函数地址
            code: 代码内容
            
        Returns:
            str: 缓存键（哈希值）
        """
        content = f"{func_ea}_{code}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def get(self, func_ea: int, code: str) -> Optional[str]:
        """
        获取缓存的分析结果
        
        Args:
            func_ea: 函数地址
            code: 代码内容
            
        Returns:
            Optional[str]: 缓存的结果，如果不存在返回 None
        """
        cache_key = self._generate_cache_key(func_ea, code)
        
        with self._lock:
            if cache_key in self.cache:
                cache_entry = self.cache[cache_key]
                # 检查缓存是否过期（24小时）
                if time.time() - cache_entry['timestamp'] < 86400:
                    print(f"📦 使用缓存结果 (函数: {hex(func_ea)})")
                    return cache_entry['result']
                else:
                    # 删除过期缓存
                    del self.cache[cache_key]
        
        return None
    
    def set(self, func_ea: int, code: str, result: str):
        """
        保存分析结果到缓存
        
        Args:
            func_ea: 函数地址
            code: 代码内容
            result: 分析结果
        """
        cache_key = self._generate_cache_key(func_ea, code)
        
        with self._lock:
            self.cache[cache_key] = {
                'func_ea': func_ea,
                'result': result,
                'timestamp': time.time()
            }
            
            # 限制缓存大小
            if len(self.cache) > MAX_CACHE_SIZE:
                # 删除最旧的条目
                oldest_key = min(self.cache.keys(), 
                               key=lambda k: self.cache[k]['timestamp'])
                del self.cache[oldest_key]
        
        self._save_cache()
    
    def _load_cache(self):
        """从文件加载缓存"""
        cache_file = self.cache_dir / 'cache.json'
        if cache_file.exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
                print(f"📦 已加载 {len(self.cache)} 条缓存记录")
            except Exception as e:
                print(f"⚠️ 加载缓存失败: {e}")
                self.cache = {}
    
    def _save_cache(self):
        """保存缓存到文件"""
        cache_file = self.cache_dir / 'cache.json'
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"⚠️ 保存缓存失败: {e}")
    
    def clear(self):
        """清空所有缓存"""
        with self._lock:
            self.cache.clear()
        self._save_cache()
        print("🗑️ 缓存已清空")


class ContextExtractor:
    """
    代码上下文提取器
    提取字符串、常量、导入函数等额外信息
    """
    
    @staticmethod
    def extract_strings(func_ea: int) -> List[str]:
        """
        提取函数中的字符串常量
        
        Args:
            func_ea: 函数地址
            
        Returns:
            List[str]: 字符串列表
        """
        strings = []
        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        
        if func_end == idaapi.BADADDR:
            return strings
        
        for ea in range(func_ea, func_end):
            # 检查是否是字符串引用
            for xref in idautils.DataRefsFrom(ea):
                str_type = idc.get_str_type(xref)
                if str_type is not None:
                    s = idc.get_strlit_contents(xref)
                    if s:
                        try:
                            decoded = s.decode('utf-8', errors='ignore')
                            if decoded and decoded not in strings:
                                strings.append(decoded)
                        except:
                            pass
        
        return strings
    
    @staticmethod
    def extract_constants(func_ea: int) -> List[int]:
        """
        提取函数中的数值常量
        
        Args:
            func_ea: 函数地址
            
        Returns:
            List[int]: 常量列表
        """
        constants = set()
        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        
        if func_end == idaapi.BADADDR:
            return list(constants)
        
        for ea in range(func_ea, func_end):
            # 提取立即数
            insn = idautils.DecodeInstruction(ea)
            if insn:
                for op in insn.ops:
                    if op.type == idaapi.o_imm:
                        val = op.value
                        # 过滤掉太小或太大的值
                        if 0 < val < 0x100000:
                            constants.add(val)
        
        return sorted(list(constants))[:20]  # 限制返回数量
    
    @staticmethod
    def get_function_info(func_ea: int) -> Dict[str, any]:
        """
        获取函数的基本信息
        
        Args:
            func_ea: 函数地址
            
        Returns:
            Dict: 函数信息字典
        """
        func_name = idc.get_func_name(func_ea)
        func_start = idc.get_func_attr(func_ea, idc.FUNCATTR_START)
        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        
        info = {
            'name': func_name,
            'address': hex(func_ea),
            'start': hex(func_start) if func_start != idaapi.BADADDR else None,
            'end': hex(func_end) if func_end != idaapi.BADADDR else None,
            'size': func_end - func_start if func_end != idaapi.BADADDR else 0,
        }
        
        return info


class PromptTemplates:
    """预设提示词模板"""
    
    # 标准分析模板
    STANDARD_ANALYSIS = """
你是一名资深的逆向工程专家。请分析以下反编译代码。

分析要求：
1. 概述主函数的核心功能
2. 识别关键算法和数据结构
3. 分析函数的输入输出
4. 简要说明子函数的作用

输出格式：
**主函数功能**：
...

**关键逻辑**：
...

**子函数说明**：
...

代码如下：
"""
    
    # 安全审计模板
    SECURITY_AUDIT = """
你是一名安全专家。请对以下代码进行安全审计。

审计重点：
1. 缓冲区溢出风险
2. 整数溢出/下溢
3. 空指针解引用
4. 未初始化变量使用
5. 格式化字符串漏洞
6. 竞态条件
7. 不安全的API调用

输出格式：
**安全风险等级**：[高/中/低]

**发现的问题**：
1. ...
2. ...

**建议修复方案**：
...

代码如下：
"""
    
    # 漏洞扫描模板
    VULNERABILITY_SCAN = """
你是一名漏洞挖掘专家。请扫描以下代码中可能存在的安全漏洞。

扫描目标：
1. 常见CVE类型漏洞
2. 内存安全问题
3. 逻辑漏洞
4. 权限绕过
5. 注入攻击向量

输出格式：
**漏洞列表**：
1. [漏洞类型] - [危害等级] - [位置]
   描述：...
   利用方式：...

**可利用性评估**：
...

代码如下：
"""
    
    # 算法识别模板
    ALGORITHM_RECOGNITION = """
你是一名算法专家。请识别以下代码中使用的算法。

识别重点：
1. 加密/解密算法（AES, RSA, DES等）
2. 哈希算法（MD5, SHA系列等）
3. 压缩算法
4. 编码算法（Base64, URL编码等）
5. 数据结构算法
6. 自定义算法

输出格式：
**识别到的算法**：
1. 算法名称：...
   算法类型：...
   用途推测：...

**算法特征**：
...

代码如下：
"""
    
    # 快速总结模板
    QUICK_SUMMARY = """
请用简洁的语言快速总结以下函数的功能（不超过3句话）：

"""
    
    @classmethod
    def get_template(cls, template_name: str) -> str:
        """
        获取指定的模板
        
        Args:
            template_name: 模板名称
            
        Returns:
            str: 模板内容
        """
        return getattr(cls, template_name, cls.STANDARD_ANALYSIS)


class ResultExporter:
    """分析结果导出器"""
    
    def __init__(self):
        """初始化导出器"""
        self.export_dir = self._get_export_dir()
    
    def _get_export_dir(self) -> Path:
        """获取导出目录路径"""
        script_dir = Path(__file__).parent
        export_dir = script_dir / EXPORT_DIR
        export_dir.mkdir(exist_ok=True)
        return export_dir
    
    def export_result(self, func_name: str, func_addr: str, 
                     result: str, code: str = "") -> str:
        """
        导出分析结果到文件
        
        Args:
            func_name: 函数名
            func_addr: 函数地址
            result: 分析结果
            code: 源代码（可选）
            
        Returns:
            str: 导出的文件路径
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{func_name}_{func_addr}_{timestamp}.md"
        filepath = self.export_dir / filename
        
        content = f"""# ComprehendAI 分析报告

## 函数信息
- **函数名**: {func_name}
- **地址**: {func_addr}
- **分析时间**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## 分析结果

{result}

"""
        
        if code:
            content += f"""
## 反编译代码

```c
{code}
```
"""
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return str(filepath)
        except Exception as e:
            print(f"❌ 导出失败: {e}")
            return ""


class DisassemblyProcessor:
    """
    反汇编代码提取处理器
    负责提取当前函数及其调用的子函数的反编译代码
    """
    
    def __init__(self, max_depth: int = DEFAULT_MAX_DEPTH, extract_context: bool = True):
        """
        初始化反汇编处理器
        
        Args:
            max_depth: 最大分析深度,控制递归提取子函数的层数
            extract_context: 是否提取额外上下文信息（字符串、常量等）
        """
        self.max_depth = max_depth
        self.extract_context = extract_context
        self._lock = Lock()
        self.context_extractor = ContextExtractor()
        self._reset_state()
        
    def _reset_state(self):
        """重置处理状态"""
        with self._lock:
            self.processed_funcs: Set[int] = set()
            self.func_disasm_list: List[str] = []
            self.main_func_ea: Optional[int] = None
    
    def get_current_function_disasm(self, include_context: bool = True) -> Tuple[str, int]:
        """
        获取当前光标位置函数的反编译代码及其子函数
        
        Args:
            include_context: 是否包含上下文信息
        
        Returns:
            Tuple[str, int]: (反编译代码字符串, 函数地址)
            
        Raises:
            ValueError: 无法定位函数起始地址
        """
        self._reset_state()
        
        current_ea = idc.get_screen_ea()
        func_start = idc.get_func_attr(current_ea, idc.FUNCATTR_START)
        
        if func_start == idaapi.BADADDR:
            raise ValueError("无法定位函数起始地址,请确保光标位于有效函数内")
        
        self.main_func_ea = func_start
        
        # 提取上下文信息
        context_info = ""
        if include_context and self.extract_context:
            context_info = self._build_context_info(func_start)
        
        # 处理函数及其子函数
        self._process_function(func_start, self.max_depth)
        
        if not self.func_disasm_list:
            raise ValueError("未能提取到任何反编译代码")
        
        result = context_info + "\n\n" + "=" * 80 + "\n\n".join(self.func_disasm_list)
        return result, func_start
    
    def _build_context_info(self, func_ea: int) -> str:
        """
        构建函数的上下文信息
        
        Args:
            func_ea: 函数地址
            
        Returns:
            str: 上下文信息字符串
        """
        info = self.context_extractor.get_function_info(func_ea)
        strings = self.context_extractor.extract_strings(func_ea)
        constants = self.context_extractor.extract_constants(func_ea)
        
        context = f"""
{'=' * 80}
函数上下文信息
{'=' * 80}
函数名: {info['name']}
地址: {info['address']}
大小: {info['size']} 字节
"""
        
        if strings:
            context += f"\n发现的字符串 ({len(strings)} 个):\n"
            for i, s in enumerate(strings[:10], 1):  # 限制显示数量
                # 截断过长的字符串
                display_s = s[:50] + "..." if len(s) > 50 else s
                context += f"  {i}. \"{display_s}\"\n"
            if len(strings) > 10:
                context += f"  ... 还有 {len(strings) - 10} 个字符串\n"
        
        if constants:
            context += f"\n关键常量 ({len(constants)} 个):\n  "
            context += ", ".join([hex(c) for c in constants[:15]])
            if len(constants) > 15:
                context += f" ... 还有 {len(constants) - 15} 个"
            context += "\n"
        
        return context
    
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
        self.last_result = ""  # 保存最后一次分析结果

    def ask_ai(self, prompt: str, ai_isRunning: Lock, 
              func_ea: int = 0, code: str = "", 
              use_cache: bool = True) -> Tuple[QueryStatus, str]:
        """
        向 AI 提出问题
        
        Args:
            prompt: 提示词
            ai_isRunning: 运行状态锁
            func_ea: 函数地址（用于缓存）
            code: 代码内容（用于缓存）
            use_cache: 是否使用缓存
            
        Returns:
            Tuple[QueryStatus, str]: (查询状态, 结果文本)
        """
        messages = [{"role": "user", "content": prompt}]
        print("\n" + "=" * 80)
        print("ComprehendAI 输出:")
        print("=" * 80 + "\n")
        
        self.stop_event.clear()  # 初始化停止事件
        
        try:
            result, answer = self._request_openai(messages)
            self.last_result = answer  # 保存结果
            return result, answer
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

    def _request_openai(self, messages: List[dict]) -> Tuple[QueryStatus, str]:
        """
        请求 OpenAI API
        
        Args:
            messages: 消息列表
            
        Returns:
            Tuple[QueryStatus, str]: (查询状态, 回答内容)
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
                    return QueryStatus.STOPPED, answer_content

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
                print("\n" + "=" * 80)
                print("✅ 分析完成！")
                print("=" * 80)
                return QueryStatus.SUCCESS, answer_content
            else:
                print("⚠️ AI 未返回有效内容")
                return QueryStatus.FAILED, ""
        
        except StopIteration as e:
            print(f"\n⚠️ 迭代被中断: {e}")
            print("\n" + "=" * 80)
            print("⏸️ 分析已停止")
            print("=" * 80)
            return QueryStatus.STOPPED, answer_content

        except Exception as e:
            print(f"\n❌ 发生错误: {e}")
            if hasattr(e, '__class__'):
                print(f"错误类型: {e.__class__.__name__}")
            traceback.print_exc()
            print("\n" + "=" * 80)
            print("❌ 分析失败，请检查配置或网络连接")
            print("=" * 80)
            return QueryStatus.FAILED, ""


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
        self.cache_manager = CacheManager()
        self.result_exporter = ResultExporter()
        self.use_cache = True  # 是否启用缓存
        self.auto_export = False  # 是否自动导出结果
        self.last_func_ea = 0
        self.last_code = ""
        
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
    
    def toggle_cache(self):
        """切换缓存开关"""
        self.use_cache = not self.use_cache
        status = "启用" if self.use_cache else "禁用"
        print(f"🔧 缓存已{status}")
    
    def toggle_auto_export(self):
        """切换自动导出开关"""
        self.auto_export = not self.auto_export
        status = "启用" if self.auto_export else "禁用"
        print(f"🔧 自动导出已{status}")
    
    def clear_cache(self):
        """清空缓存"""
        self.cache_manager.clear()
    
    def export_last_result(self):
        """导出上次分析结果"""
        if not self.ai_service.last_result:
            print("❌ 没有可导出的结果")
            return
        
        func_name = idc.get_func_name(self.last_func_ea) or "unknown"
        func_addr = hex(self.last_func_ea) if self.last_func_ea else "0x0"
        
        filepath = self.result_exporter.export_result(
            func_name, func_addr, 
            self.ai_service.last_result,
            self.last_code
        )
        
        if filepath:
            print(f"✅ 结果已导出到: {filepath}")
    
    def _create_analysis_prompt(self, disassembly: str, template: str = None) -> str:
        """
        创建分析提示词
        
        Args:
            disassembly: 反汇编代码
            template: 提示词模板（可选）
            
        Returns:
            str: 完整提示词
        """
        if template:
            return template + "\n" + disassembly
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
    
    def create_ai_task(self, task_type: TaskType, question: str = "", template_name: str = ""):
        """
        创建 AI 分析任务
        
        Args:
            task_type: 任务类型
            question: 用户问题(仅部分任务类型需要)
            template_name: 模板名称(仅部分任务类型需要)
        """
        try:
            match task_type:
                case TaskType.ANALYSIS:
                    self._handle_analysis(template_name)
                    
                case TaskType.CUSTOM_QUERY:
                    if not question:
                        print("❌ 请提供问题内容")
                        return
                    self._async_task(question, 0, "")
                    
                case TaskType.CUSTOM_QUERY_WITH_CODE:
                    if not question:
                        print("❌ 请提供问题内容")
                        return
                    print("📝 正在提取反汇编代码...")
                    disassembly, func_ea = self.disassembler.get_current_function_disasm()
                    self.last_func_ea = func_ea
                    self.last_code = disassembly
                    prompt = self._create_custom_query_with_code(disassembly, question)
                    self._async_task(prompt, func_ea, disassembly)
                
                case TaskType.SECURITY_AUDIT:
                    self._handle_analysis("SECURITY_AUDIT")
                
                case TaskType.VULNERABILITY_SCAN:
                    self._handle_analysis("VULNERABILITY_SCAN")
                    
        except ValueError as e:
            print(f"❌ {str(e)}")
        except Exception as e:
            print(f"❌ 创建任务失败: {str(e)}")
            traceback.print_exc()
    
    def _handle_analysis(self, template_name: str = ""):
        """
        处理代码分析任务
        
        Args:
            template_name: 模板名称
        """
        print("📝 正在提取反汇编代码...")
        disassembly, func_ea = self.disassembler.get_current_function_disasm()
        self.last_func_ea = func_ea
        self.last_code = disassembly
        
        # 检查缓存
        if self.use_cache:
            cached_result = self.cache_manager.get(func_ea, disassembly)
            if cached_result:
                print(cached_result)
                self.ai_service.last_result = cached_result
                
                if self.auto_export:
                    self.export_last_result()
                
                return
        
        # 创建提示词
        if template_name:
            template = PromptTemplates.get_template(template_name)
            prompt = self._create_analysis_prompt(disassembly, template)
        else:
            prompt = self._create_analysis_prompt(disassembly)
        
        # 执行分析
        self._async_task(prompt, func_ea, disassembly)
        
    def _async_task(self, prompt: str, func_ea: int = 0, code: str = ""):
        """
        异步执行 AI 任务
        
        Args:
            prompt: 提示词
            func_ea: 函数地址
            code: 代码内容
        """
        if self.ai_isRunning.acquire(blocking=False):
            # 在新线程中执行 AI 请求
            task = Thread(
                target=self._run_ai_task,
                args=(prompt, func_ea, code),
                daemon=True  # 设置为守护线程
            )
            task.start()
            print("🚀 AI 任务已启动...")
        else:
            print("❌ 当前 AI 正在处理任务,请稍后尝试或使用 Stop 停止当前任务")
    
    def _run_ai_task(self, prompt: str, func_ea: int, code: str):
        """
        运行 AI 任务并处理结果
        
        Args:
            prompt: 提示词
            func_ea: 函数地址
            code: 代码内容
        """
        status, result = self.ai_service.ask_ai(
            prompt, 
            self.ai_isRunning,
            func_ea,
            code,
            self.use_cache
        )
        
        # 保存到缓存
        if status == QueryStatus.SUCCESS and result and func_ea and self.use_cache:
            self.cache_manager.set(func_ea, code, result)
        
        # 自动导出
        if status == QueryStatus.SUCCESS and result and self.auto_export:
            self.export_last_result()
    
    def stop(self):
        """停止当前 AI 任务"""
        if self.ai_service.stop_event.is_set():
            print("ℹ️ 没有正在运行的任务")
        else:
            self.ai_service.stop_event.set()
            print("🛑 正在停止任务...")
    
    def choose_template(self) -> Optional[str]:
        """
        让用户选择提示词模板
        
        Returns:
            Optional[str]: 选择的模板名称
        """
        templates = {
            "1": ("标准分析", "STANDARD_ANALYSIS"),
            "2": ("安全审计", "SECURITY_AUDIT"),
            "3": ("漏洞扫描", "VULNERABILITY_SCAN"),
            "4": ("算法识别", "ALGORITHM_RECOGNITION"),
            "5": ("快速总结", "QUICK_SUMMARY"),
        }
        
        print("\n可用模板:")
        for key, (name, _) in templates.items():
            print(f"{key}. {name}")
        
        choice = idaapi.ask_str("1", 0, "选择模板 (输入数字):")
        if choice and choice in templates:
            return templates[choice][1]
        
        return None

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
        # 基础分析
        ("AI_analysis:Analysis", "🤖 AI 智能分析", "执行标准AI代码分析"),
        ("AI_analysis:SecurityAudit", "🔒 安全审计", "深度安全漏洞审计"),
        ("AI_analysis:VulnerabilityScan", "🐛 漏洞扫描", "扫描潜在安全漏洞"),
        ("AI_analysis:AlgorithmRecognition", "🔍 算法识别", "识别加密和算法"),
        ("AI_analysis:QuickSummary", "⚡ 快速总结", "快速总结函数功能"),
        
        # 自定义查询
        ("AI_analysis:CustomQueryWithCode", "💬 带代码提问", "结合当前代码向AI提问"),
        ("AI_analysis:CustomQuery", "💭 直接提问", "直接向AI提问"),
        
        # 结果管理
        ("AI_analysis:ExportResult", "💾 导出结果", "导出上次分析结果"),
        ("AI_analysis:ToggleAutoExport", "📤 自动导出", "切换自动导出开关"),
        
        # 缓存管理
        ("AI_analysis:ToggleCache", "🔄 切换缓存", "启用/禁用结果缓存"),
        ("AI_analysis:ClearCache", "🗑️ 清空缓存", "清除所有缓存数据"),
        
        # 配置
        ("AI_analysis:SetDepth", "⚙️ 分析深度", "设置函数分析递归深度"),
        ("AI_analysis:SetPrompt", "📝 自定义提示词", "自定义分析提示词模板"),
        
        # 控制
        ("AI_analysis:Stop", "🛑 停止", "停止当前AI任务"),
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
                    # 基础分析功能
                    case "AI_analysis:Analysis":
                        self.handler.create_ai_task(TaskType.ANALYSIS)
                    
                    case "AI_analysis:SecurityAudit":
                        self.handler.create_ai_task(TaskType.SECURITY_AUDIT)
                    
                    case "AI_analysis:VulnerabilityScan":
                        self.handler.create_ai_task(TaskType.VULNERABILITY_SCAN)
                    
                    case "AI_analysis:AlgorithmRecognition":
                        self.handler.create_ai_task(TaskType.ANALYSIS, template_name="ALGORITHM_RECOGNITION")
                    
                    case "AI_analysis:QuickSummary":
                        self.handler.create_ai_task(TaskType.ANALYSIS, template_name="QUICK_SUMMARY")
                    
                    # 自定义查询
                    case "AI_analysis:CustomQuery":
                        question = idaapi.ask_text(0, "", "请输入您的问题:")
                        if question:
                            self.handler.create_ai_task(TaskType.CUSTOM_QUERY, question)
                    
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
                    
                    # 结果管理
                    case "AI_analysis:ExportResult":
                        self.handler.export_last_result()
                    
                    case "AI_analysis:ToggleAutoExport":
                        self.handler.toggle_auto_export()
                    
                    # 缓存管理
                    case "AI_analysis:ToggleCache":
                        self.handler.toggle_cache()
                    
                    case "AI_analysis:ClearCache":
                        if idaapi.ask_yn(1, "确定要清空所有缓存吗？") == 1:
                            self.handler.clear_cache()
                    
                    # 配置
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
                    
                    # 控制
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