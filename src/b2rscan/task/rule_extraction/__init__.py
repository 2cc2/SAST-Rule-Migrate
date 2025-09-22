# -*- coding: utf-8 -*-
"""
规则提取器模块
该模块负责从不同SAST工具中提取规则并转换为统一的xCPG-IR格式
"""

from .extractor import RuleExtractor
from .ir_converter import IRConverter
from .parser import BaseRuleParser, CodeQLRuleParser

__all__ = ['RuleExtractor', 'IRConverter', 'BaseRuleParser', 'CodeQLRuleParser']