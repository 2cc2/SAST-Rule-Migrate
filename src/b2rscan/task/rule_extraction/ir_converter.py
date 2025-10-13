# -*- coding: utf-8 -*-
"""
xCPG-IR转换器
将不同SAST工具提取的规则转换为统一的xCPG-IR格式
"""

from typing import List, Dict, Any, Optional
from dataclasses import asdict

from b2rscan.xcpg_ir.schema import XCPGIR
from b2rscan.xcpg_ir.flow import RuleMetadata, Scope, Environment, Report, TestCases, Flow
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
            # 确保rule是一个字典
            if not isinstance(rule, dict):
                print(f"规则不是字典类型: {type(rule)}")
                return None
                
            # 创建基础元数据
            rule_metadata = RuleMetadata(
                id=str(rule.get("id", f"{source_tool}-{hash(str(rule))}")),
                kind=RuleKind(rule.get("kind", "taint")),
                severity=SeverityLevel(rule.get("severity", "medium")),
                message=str(rule.get("message", rule.get("description", "Security rule")))
            )
            
            # 创建作用域
            scope_data = rule.get("scope", {})
            if not isinstance(scope_data, dict):
                scope_data = {}
                
            scope = Scope(
                languages=scope_data.get("languages", ["*"]),
                frameworks=scope_data.get("frameworks", ["*"]),
                env=Environment(
                    os=scope_data.get("env", {}).get("os", ["*"]),
                    shell=scope_data.get("env", {}).get("shell", ["*"])
                ) if scope_data.get("env") else None
            )
            
            # 转换sources
            sources = []
            for source in rule.get("sources", []):
                if isinstance(source, dict):
                    sources.append(Source(
                        id=str(source.get("id", f"source-{len(sources)}")),
                        match=self._create_match(source)
                    ))
            
            # 转换sinks
            sinks = []
            for sink in rule.get("sinks", []):
                if isinstance(sink, dict):
                    sinks.append(Sink(
                        id=str(sink.get("id", f"sink-{len(sinks)}")),
                        match=self._create_match(sink)
                    ))
            
            # 转换sanitizers
            sanitizers = []
            for sanitizer in rule.get("sanitizers", []):
                if isinstance(sanitizer, dict):
                    sanitizers.append(Sanitizer(
                        id=str(sanitizer.get("id", f"sanitizer-{len(sanitizers)}")),
                        match=self._create_match(sanitizer),
                        effect=sanitizer.get("effect", "neutralize")
                    ))
            
            # 转换barriers
            barriers = []
            for barrier in rule.get("barriers", []):
                if isinstance(barrier, dict):
                    barriers.append(Barrier(
                        id=str(barrier.get("id", f"barrier-{len(barriers)}")),
                        match=self._create_match(barrier),
                        effect=barrier.get("effect", "stop")
                    ))
            
            # 转换propagations
            propagations = []
            for propagation in rule.get("propagations", []):
                if isinstance(propagation, dict):
                    propagations.append(Propagation(
                        id=str(propagation.get("id", f"propagation-{len(propagations)}")),
                        edge=str(propagation.get("edge", "arg->param")),
                        kind=str(propagation.get("kind", "taint"))
                    ))
            
            # 转换flows
            flows = []
            for flow in rule.get("flows", []):
                if isinstance(flow, dict):
                    flows.append(Flow(
                        source=str(flow.get("source", "")),
                        sink=str(flow.get("sink", "")),
                        through=flow.get("through", []),
                    ))
            
            # 创建报告
            report_data = rule.get("report", {})
            if not isinstance(report_data, dict):
                report_data = {}
                
            report = Report(
                message=str(report_data.get("message", "Security rule violation detected")),
                locations=report_data.get("locations", ["source", "sink"])
            )
            
            # 创建测试用例
            tests_data = rule.get("tests", {})
            if not isinstance(tests_data, dict):
                tests_data = {}
                
            tests = TestCases(
                positive=tests_data.get("positive", []),
                negative=tests_data.get("negative", [])
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