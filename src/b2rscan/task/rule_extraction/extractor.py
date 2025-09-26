import os
import json
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
        
    def extract_rules(self, sast_tool: str, source_path: str, options: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        使用agent从指定的SAST工具中提取规则
        
        Args:
            sast_tool: SAST工具名称 (如 'codeql', 'semgrep' 等)
            source_path: 规则源码路径
            options: 提取选项
            
        Returns:
            提取的规则列表
        """
        if options is None:
            options = {}
            
        # 构造更具元认知能力的任务描述
        task_description = f"""
        You are a security rule extraction expert. Your task is to analyze the {sast_tool} repository 
        located at {source_path} and extract security rules, then convert them to our unified xCPG-IR format.
        
        First, think about the approach:
        1. Understand the structure and organization of the {sast_tool} repository
        2. Identify where security rules are defined (file patterns, directory structures)
        3. Recognize the rule format used by {sast_tool} (YAML, JSON, custom DSL, etc.)
        4. Analyze example rules to understand their components and semantics
        
        Then, for each rule you find:
        1. Extract the rule ID, name, and description
        2. Determine the rule's severity level
        3. Identify sources, sinks, sanitizers and barriers in the rule
        4. Map these elements to the xCPG-IR schema as defined in the XCPG-IR Specification v1.0
        
        Rule extraction strategy:
        - Look for files with extensions like .yml, .yaml, .json, .ql (for CodeQL)
        - Examine directories like 'rules', 'queries', 'patterns', 'detections'
        - Consider both built-in rules and example rules
        - Pay attention to rule metadata and configuration files
        
        Output requirements:
        1. Return a JSON array of rules in xCPG-IR format
        2. Each rule must follow the XCPG-IR schema with all required fields
        3. Include proper sources, sinks, sanitizers, barriers, and flows
        4. Ensure the output is valid against the XCPG-IR schema
        5. Do not include explanatory text, only the JSON array
        
        Additional context: {json.dumps(options)}
        """
        
        result = self.llm_client.infer(task_description)
        
        # 尝试解析JSON结果
        try:
            rules = json.loads(result)
            # 转换为XCPG-IR并验证
            xcpg_ir_rules = self.ir_converter.convert(rules, sast_tool)
            # 转换为字典列表以便返回
            return [asdict(ir_rule) for ir_rule in xcpg_ir_rules]
        except json.JSONDecodeError:
            print("Failed to parse LLM response as JSON")
            return []

if __name__ == "__main__":
    extractor = RuleExtractor()
    rules = extractor.extract_rules("codeql", "sast/codeql")
    #print(rules)