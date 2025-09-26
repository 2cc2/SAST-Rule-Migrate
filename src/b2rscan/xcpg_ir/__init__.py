# -*- coding: utf-8 -*-
"""
XCPG-IR模块
统一的中间表示定义
"""

from .schema import XCPGIR
from .validator import XCPGIRValidator
from .types import RuleKind, SeverityLevel, NodeKind
from .entities import Source, Sink, Sanitizer, Barrier, Propagation
from .flow import RuleMetadata, Scope, Flow, Report, TestCases

__all__ = [
    'XCPGIR',
    'XCPGIRValidator',
    'RuleKind',
    'SeverityLevel',
    'NodeKind',
    'Source',
    'Sink',
    'Sanitizer',
    'Barrier',
    'Propagation',
    'RuleMetadata',
    'Scope',
    'Flow',
    'Report',
    'TestCases'
]