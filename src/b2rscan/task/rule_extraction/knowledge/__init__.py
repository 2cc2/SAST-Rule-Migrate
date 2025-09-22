# -*- coding: utf-8 -*-
"""
规则知识库模块
该模块负责管理规则相关的知识库，包括：
- 污点传播模式
- 净化函数
- 验证函数
- API别名等
"""

class KnowledgeBase:
    """
    规则知识库类
    """
    
    def __init__(self):
        self.sources = set()
        self.sinks = set()
        self.sanitizers = set()
        self.validators = set()
        self.api_aliases = {}
    
    def add_source(self, source: str):
        """添加污点源"""
        self.sources.add(source)
    
    def add_sink(self, sink: str):
        """添加污点汇聚点"""
        self.sinks.add(sink)
    
    def add_sanitizer(self, sanitizer: str):
        """添加净化函数"""
        self.sanitizers.add(sanitizer)
    
    def add_validator(self, validator: str):
        """添加验证函数"""
        self.validators.add(validator)
    
    def add_api_alias(self, alias: str, real_api: str):
        """添加API别名"""
        self.api_aliases[alias] = real_api

# 全局知识库实例
knowledge_base = KnowledgeBase()