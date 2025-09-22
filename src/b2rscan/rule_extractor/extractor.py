import os
from typing import Dict, Any, List, Optional
# from .parser import CodeQLRuleParser
# from .ir_converter import IRConverter
from b2rscan.llm_wrapper import LLMWrapper

class RuleExtractor:
   
    def __init__(self, config_path: Optional[str] = None):
        """
        初始化规则提取器
        """
        
        # self.codeql_parser = CodeQLRuleParser()
        # self.ir_converter = IRConverter()
        self.llm_client = LLMWrapper("dashscope")
        
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
        3. Identify sources, sinks, sanitizers and validators in the rule
        4. Map these elements to the xCPG-IR schema
        
        Rule extraction strategy:
        - Look for files with extensions like .yml, .yaml, .json, .ql (for CodeQL)
        - Examine directories like 'rules', 'queries', 'patterns', 'detections'
        - Consider both built-in rules and example rules
        - Pay attention to rule metadata and configuration files
        
        Output requirements:
        1. Return a JSON array of rules in xCPG-IR format
        2. Each rule must include: id, name, description, severity, sources, sinks, sanitizers, validators
        3. Ensure the output follows the xCPG-IR schema
        4. If you cannot find specific information, use appropriate default values
        5. Do not include explanatory text, only the JSON array
        
        Additional context: {options}
        """
        
        result = self.llm_client.infer(task_description)
        print(result)
        # 解析结果并返回规则列表
        # 在实际实现中，这里需要解析agent的输出结果
        # 目前返回一个示例结构
        rules = [
            {
                "id": f"{sast_tool}-example-rule-1",
                "name": "Example Rule",
                "source": sast_tool,
                "pattern": "example-pattern",
                "severity": "high",
                "description": "Example rule extracted by agent",
                "sources": ["example-source"],
                "sinks": ["example-sink"],
                "sanitizers": ["example-sanitizer"],
                "validators": ["example-validator"]
            }
        ]
        
        return rules
        

if __name__ == "__main__":
    extractor = RuleExtractor()
    rules = extractor.extract_rules("codeql", "sast/codeql")
    #print(rules)