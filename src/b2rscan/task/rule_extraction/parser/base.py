# -*- coding: utf-8 -*-
"""
解析器基类
定义所有SAST工具规则解析器的通用接口
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any


class BaseRuleParser(ABC):
    """
    规则解析器基类
    """
    
    def __init__(self):
        pass
    
    @abstractmethod
    def parse(self, source: str) -> List[Dict[str, Any]]:
        """
        解析规则源文件并返回规则列表
        
        Args:
            source: 规则源文件路径或内容
            
        Returns:
            解析后的规则列表，每个规则为字典格式
        """
        pass
    
    @abstractmethod
    def validate(self, rule: Dict[str, Any]) -> bool:
        """
        验证规则格式是否正确
        
        Args:
            rule: 待验证的规则字典
            
        Returns:
            验证结果
        """
        pass