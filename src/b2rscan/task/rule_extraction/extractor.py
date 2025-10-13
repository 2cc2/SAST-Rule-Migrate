import os
import json
import glob
from typing import Dict, Any, List, Optional
from dataclasses import asdict

from b2rscan.llm_wrapper import LLMWrapper
from b2rscan.xcpg_ir.validator import XCPGIRValidator
from b2rscan.task.rule_extraction.ir_converter import IRConverter

class RuleExtractor:
   
    def __init__(self, config_path: Optional[str] = None):
        """
        初始化规则提取器
        """
        self.llm_client = LLMWrapper("dashscope")
        self.ir_converter = IRConverter()
        
    def _get_rule_files(self, sast_tool: str, source_path: str) -> List[str]:
        """获取规则文件列表"""
        rule_files = []
        
        # 根据SAST工具确定规则文件扩展名
        extensions = {
            "codeql": [".ql"],
            "semgrep": [".yaml", ".yml"],
            "gosec": [".go"],
            "bandit": [".py"],
            "pmd": [".xml", ".xsl"],
            "findsecbugs": [".xml"]
        }.get(sast_tool, [".yaml", ".yml", ".json", ".ql", ".go", ".py"])
        
        # 遍历目录查找规则文件
        for root, _, files in os.walk(source_path):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    rule_files.append(os.path.join(root, file))
                    
        return rule_files
    
    def _read_rule_content(self, file_path: str, max_chars: int = 2000) -> str:
        """读取规则文件内容（限制字符数）"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                if len(content) > max_chars:
                    return content[:max_chars] + "\n# ... 内容截断 ...\n"
                return content
        except Exception as e:
            return f"# 无法读取文件: {str(e)}"
    
    def _get_tool_description(self, sast_tool: str) -> str:
        """获取SAST工具的描述"""
        descriptions = {
            "codeql": "CodeQL是一种基于语义的代码分析引擎，使用QL查询语言定义安全规则。QL是一种逻辑编程语言，规则通常包含from、where、select子句。",
            "semgrep": "Semgrep是一种快速、轻量级的静态分析工具，使用YAML规则格式。规则包含模式匹配和元数据。",
            "gosec": "GoSec是Go语言的安全扫描器，规则嵌入在Go源代码中，使用注释标记。",
            "bandit": "Bandit是Python代码的静态分析工具，规则使用YAML格式定义，专注于安全问题检测。",
            "pmd": "PMD是一种源代码分析工具，规则使用XML格式定义XPath表达式来匹配代码模式。",
            "findsecbugs": "FindSecBugs是FindBugs的插件，使用XML配置检测Java安全漏洞。"
        }
        return descriptions.get(sast_tool, sast_tool.capitalize())
    
    def _extract_rule_from_content(self, sast_tool: str, file_path: str, rule_content: str) -> Optional[Dict[str, Any]]:
        """使用LLM从规则内容提取XCPG-IR"""
        tool_desc = self._get_tool_description(sast_tool)
        
        # 构造LLM提示
        prompt = f"""
你是一名安全规则转换专家。你的任务是将以下{sast_tool}规则转换为XCPG-IR格式。

{sast_tool}工具描述：
{tool_desc}

规则文件路径：{file_path}

{sast_tool}规则内容：
{rule_content}

XCPG-IR规范v1.0要求：
1. 必须包含rule部分（id, kind, severity, message）
2. 必须定义scope（languages, frameworks, env）
3. 必须识别sources, sinks, sanitizers, barriers
4. 必须定义propagations和flows
5. 必须提供report和tests

请按照以下步骤操作：
1. 分析规则的功能和意图
2. 识别源点(sources)和汇点(sinks)
3. 确定净化器(sanitizers)和屏障(barriers)
4. 描述数据流(flows)和传播(propagations)
5. 生成符合XCPG-IR规范的JSON

输出要求：
1. 仅输出JSON格式的XCPG-IR，不要包含任何其他解释
2. 必须包含所有必需字段
3. 对于不确定的字段，使用合理的默认值或推断值
4. 保持JSON格式正确

示例XCPG-IR格式：
{{
  "xcpgir_version": "1.0",
  "rule": {{
    "id": "rule-id",
    "kind": "taint",
    "severity": "warning",
    "message": "规则描述"
  }},
  "scope": {{
    "languages": ["java"],
    "frameworks": ["*"]
  }},
  "sources": [...],
  "sinks": [...],
  "sanitizers": [...],
  "barriers": [...],
  "propagations": [...],
  "flows": [...],
  "report": {{
    "message": "检测到安全问题",
    "locations": ["source", "sink"]
  }},
  "tests": {{
    "positive": ["示例代码"],
    "negative": ["安全代码"]
  }}
}}

注意：如果规则不包含某些信息，请根据规则功能合理推断。只输出JSON，不要包含其他文本。
"""
        
        # 调用LLM进行转换
        response = self.llm_client.infer(prompt)
        
        try:
            # 尝试解析JSON
            return json.loads(response)
        except json.JSONDecodeError:
            print(f"Failed to parse LLM response for {file_path}: {response}")
            return None

    def extract_rules(self, sast_tool: str, source_path: str, options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        使用LLM从指定的SAST工具中提取规则并转换为XCPG-IR
        
        Args:
            sast_tool: SAST工具名称 (如 'codeql', 'semgrep' 等)
            source_path: 规则源码路径
            options: 提取选项
            
        Returns:
            提取并转换后的XCPG-IR规则列表
        """
        if options is None:
            options = {}
            
        # 获取规则文件列表
        rule_files = self._get_rule_files(sast_tool, source_path)
        if not rule_files:
            print(f"在 {source_path} 中未找到 {sast_tool} 规则文件")
            return []
            
        print(f"找到 {len(rule_files)} 个 {sast_tool} 规则文件，开始转换...")
        
        # 逐个处理规则文件
        xcpg_ir_rules = []
        for i, file_path in enumerate(rule_files):
            if "CWE-089" not in file_path:
                continue
            print(f"处理规则文件 [{i+1}/{len(rule_files)}]: {os.path.basename(file_path)}")
            
            # 读取规则内容
            rule_content = self._read_rule_content(file_path)
            
            # 使用LLM提取规则
            rule_ir = self._extract_rule_from_content(sast_tool, file_path, rule_content)
            
            if rule_ir:
                # 转换为XCPG-IR并验证
                converted_rules = self.ir_converter.convert([rule_ir], sast_tool)
                if converted_rules:
                    xcpg_ir_rules.extend(converted_rules)
                    print(f"  成功转换为XCPG-IR")
                else:
                    print(f"  转换失败: 无法将规则转换为有效的XCPG-IR")
            else:
                print(f"  转换失败: 无法从LLM获取有效响应")
        
        # 转换为字典列表以便返回
        return [asdict(ir_rule) for ir_rule in xcpg_ir_rules]

if __name__ == "__main__":
    extractor = RuleExtractor()
    rules = extractor.extract_rules("codeql", "sast/codeql")
    #print(rules)