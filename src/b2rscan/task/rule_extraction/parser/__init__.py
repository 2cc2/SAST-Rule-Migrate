# -*- coding: utf-8 -*-
"""
规则解析器模块
包含针对不同SAST工具的规则解析器
"""

from .base import BaseRuleParser
from .codeql_parser import CodeQLRuleParser

__all__ = ['BaseRuleParser', 'CodeQLRuleParser']