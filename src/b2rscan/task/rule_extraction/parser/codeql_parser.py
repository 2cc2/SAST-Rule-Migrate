# -*- coding: utf-8 -*-
"""
CodeQL规则解析器
用于解析CodeQL查询文件并提取规则信息
"""

import os
from typing import List, Dict, Any
from .base import BaseRuleParser


class CodeQLRuleParser(BaseRuleParser):
    """
    CodeQL规则解析器
    """
    
    def __init__(self):
        super().__init__()
        self.supported_extensions = ['.ql', '.qll']
    
    def parse(self, source: str) -> List[Dict[str, Any]]:
        """
        解析CodeQL规则源文件
        
        Args:
            source: CodeQL规则文件路径
            
        Returns:
            解析后的规则列表
        """
        rules = []
        
        if os.path.isfile(source):
            # 单个文件
            if any(source.endswith(ext) for ext in self.supported_extensions):
                rule = self._parse_single_file(source)
                if rule:
                    rules.append(rule)
        elif os.path.isdir(source):
            # 目录
            for root, _, files in os.walk(source):
                for file in files:
                    if any(file.endswith(ext) for ext in self.supported_extensions):
                        file_path = os.path.join(root, file)
                        rule = self._parse_single_file(file_path)
                        if rule:
                            rules.append(rule)
        
        return rules
    
    def _parse_single_file(self, file_path: str) -> Dict[str, Any]:
        """
        解析单个CodeQL文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            解析后的规则字典
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 简单解析CodeQL文件
            # 实际实现中需要更复杂的解析逻辑
            rule = {
                "id": os.path.basename(file_path),
                "name": os.path.splitext(os.path.basename(file_path))[0],
                "source": "codeql",
                "file_path": file_path,
                "content": content
            }
            
            return rule
        except Exception as e:
            print(f"解析文件 {file_path} 时出错: {e}")
            return None
    
    def validate(self, rule: Dict[str, Any]) -> bool:
        """
        验证CodeQL规则格式
        
        Args:
            rule: 待验证的规则字典
            
        Returns:
            验证结果
        """
        required_fields = ['id', 'name', 'source', 'file_path']
        return all(field in rule for field in required_fields)