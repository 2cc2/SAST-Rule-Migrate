# -*- coding: utf-8 -*-
"""
xCPG-IR转换器
将不同SAST工具提取的规则转换为统一的xCPG-IR格式
"""

from typing import List, Dict, Any, Optional
from dataclasses import asdict

from b2rscan.xcpg_ir.schema import XCPGIR
from b2rscan.xcpg_ir.flow import RuleMetadata, Scope, Environment, Report, TestCases
from b2rscan.xcpg_ir.entities import Source, Sink, Sanitizer, Barrier, Propagation
from b2rscan.xcpg_ir.validator import XCPGIRValidator
from b2rscan.xcpg_ir.match import Match, ApiSignature, TypeMatch, WhereClause
from b2rscan.xcpg_ir.types import RuleKind, SeverityLevel, NodeKind

class IRConverter:
    """
    xCPG-IR转换器
    """
    
    def __init__(self):
        pass
    
    def convert(self, rules: List[Dict[str, Any]], source_tool: str) -> List[XCPGIR]:
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
            if ir_rule and XCPGIRValidator.validate(ir_rule):
                converted_rules.append(ir_rule)
        
        return converted_rules
    
    def _to_ir_format(self, rule: Dict[str, Any], source_tool: str) -> Optional[XCPGIR]:
        """
        将单个规则转换为xCPG-IR格式
        
        Args:
            rule: 原始规则
            source_tool: 源SAST工具名称
            
        Returns:
            xCPG-IR格式的规则或None（如果转换失败）
        """
        try:
            # 创建基础元数据
            rule_metadata = RuleMetadata(
                id=rule.get("id", f"{source_tool}-{hash(str(rule))}"),
                kind=rule.get("kind", "taint"),
                severity=rule.get("severity", "medium"),
                message=rule.get("description", "Security rule")
            )
            
            # 创建作用域
            scope = Scope(
                languages=rule.get("languages", ["*"]),
                frameworks=rule.get("frameworks", ["*"]),
                env=Environment(
                    os=rule.get("os", ["*"]),
                    shell=rule.get("shell", ["*"])
                ) if rule.get("os") or rule.get("shell") else None
            )
            
            # 转换sources
            sources = []
            for source in rule.get("sources", []):
                sources.append(Source(
                    id=source.get("id", f"source-{len(sources)}"),
                    match=self._create_match(source)
                ))
            
            # 转换sinks
            sinks = []
            for sink in rule.get("sinks", []):
                sinks.append(Sink(
                    id=sink.get("id", f"sink-{len(sinks)}"),
                    match=self._create_match(sink)
                ))
            
            # 转换sanitizers
            sanitizers = []
            for sanitizer in rule.get("sanitizers", []):
                sanitizers.append(Sanitizer(
                    id=sanitizer.get("id", f"sanitizer-{len(sanitizers)}"),
                    match=self._create_match(sanitizer),
                    effect=sanitizer.get("effect", "neutralize"),
                    effect_config=self._create_sanitizer_effect(sanitizer)
                ))
            
            # 转换barriers
            barriers = []
            for barrier in rule.get("barriers", []):
                barriers.append(Barrier(
                    id=barrier.get("id", f"barrier-{len(barriers)}"),
                    match=self._create_match(barrier),
                    effect=barrier.get("effect", "stop")
                ))
            
            # 转换propagations
            propagations = []
            for propagation in rule.get("propagations", []):
                propagations.append(Propagation(
                    id=propagation.get("id", f"propagation-{len(propagations)}"),
                    edge=propagation.get("edge", "arg->param"),
                    kind=propagation.get("kind", "taint")
                ))
            
            # 转换flows
            flows = []
            for flow in rule.get("flows", []):
                flows.append(Flow(
                    source=flow.get("source", ""),
                    sink=flow.get("sink", ""),
                    through=flow.get("through", []),
                    constraints=self._create_flow_constraints(flow)
                ))
            
            # 创建报告
            report = Report(
                message=rule.get("description", "Security rule violation detected"),
                locations=rule.get("locations", ["source", "sink"]),
                evidence=self._create_evidence(rule)
            )
            
            # 创建测试用例
            tests = TestCases(
                positive=rule.get("positive_tests", []),
                negative=rule.get("negative_tests", [])
            )
            
            # 构建完整XCPG-IR
            return XCPGIR(
                rule=rule_metadata,
                scope=scope,
                sources=sources,
                sinks=sinks,
                sanitizers=sanitizers,
                barriers=barriers,
                propagations=propagations,
                flows=flows,
                report=report,
                tests=tests
            )
        except Exception as e:
            print(f"Error converting rule to XCPG-IR: {str(e)}")
            return None
    
    def _create_match(self, entity: Dict[str, Any]) -> Match:
        """创建Match对象"""
        api = None
        if "api" in entity:
            api_data = entity["api"]
            api = ApiSignature(
                package=api_data.get("package"),
                type=api_data.get("type"),
                method=api_data.get("method"),
                signature=api_data.get("signature")
            )
        
        type_match = None
        if "type" in entity:
            type_data = entity["type"]
            type_match = TypeMatch(
                name=type_data.get("name"),
                match=type_data.get("match")
            )
        
        where_clauses = None
        if "where" in entity:
            where_clauses = []
            for clause in entity["where"]:
                where_clauses.append(WhereClause(
                    op=clause.get("op", "eq"),
                    left=clause.get("left", ""),
                    right=clause.get("right")
                ))
        
        return Match(
            node=entity.get("node", "CALL"),
            api=api,
            type=type_match,
            arg_index=entity.get("arg_index"),
            where=where_clauses
        )
    
    def _create_sanitizer_effect(self, sanitizer: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """创建sanitizer effect配置"""
        if "effect_config" in sanitizer:
            return sanitizer["effect_config"]
        return None
    
    def _create_flow_constraints(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """创建flow constraints"""
        if "constraints" in flow and "path" in flow["constraints"]:
            return flow["constraints"]
        return None
    
    def _create_evidence(self, rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """创建evidence配置"""
        if "evidence" in rule:
            return rule["evidence"]
        return None