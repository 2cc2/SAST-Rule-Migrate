# -*- coding: utf-8 -*-
"""
xCPG-IR转换器
将不同SAST工具提取的规则转换为统一的xCPG-IR格式
"""

from typing import List, Dict, Any


class IRConverter:
    """
    xCPG-IR转换器
    """
    
    def __init__(self):
        pass
    
    def convert(self, rules: List[Dict[str, Any]], source_tool: str) -> List[Dict[str, Any]]:
        """
        将规则转换为xCPG-IR格式
        
        Args:
            rules: 提取的规则列表
            source_tool: 源SAST工具名称
            
        Returns:
            转换后的xCPG-IR规则列表
        """
        converted_rules = []
        
        for rule in rules:
            ir_rule = self._to_ir_format(rule, source_tool)
            if ir_rule:
                converted_rules.append(ir_rule)
        
        return converted_rules
    
    def _to_ir_format(self, rule: Dict[str, Any], source_tool: str) -> Dict[str, Any]:
        """
        将单个规则转换为xCPG-IR格式
        
        Args:
            rule: 原始规则
            source_tool: 源SAST工具名称
            
        Returns:
            xCPG-IR格式的规则
        """
        # xCPG-IR标准格式
        ir_rule = {
            "id": rule.get("id", ""),
            "name": rule.get("name", ""),
            "description": rule.get("description", ""),
            "severity": rule.get("severity", "medium"),
            "source": source_tool,
            "sources": rule.get("sources", []),
            "sinks": rule.get("sinks", []),
            "sanitizers": rule.get("sanitizers", []),
            "validators": rule.get("validators", []),
            "pattern": rule.get("pattern", ""),
            "metadata": {
                "original": rule
            }
        }
        
        return ir_rule
    
    def validate_ir(self, ir_rule: Dict[str, Any]) -> bool:
        """
        验证xCPG-IR规则格式
        
        Args:
            ir_rule: xCPG-IR格式的规则
            
        Returns:
            验证结果
        """
        required_fields = ['id', 'name', 'description', 'severity', 'sources', 'sinks']
        return all(field in ir_rule for field in required_fields)