import json
from typing import List, Dict, Optional, Union, Any
from dataclasses import asdict, is_dataclass
import jsonschema
from jsonschema import validate
from .schema import XCPGIR
from .types import SeverityLevel, RuleKind

class XCPGIRValidator:
    """XCPG-IR验证器"""
    
    SCHEMA = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "XCPG-IR Schema",
        "type": "object",
        "properties": {
            "xcpgir_version": {"type": "string", "default": "1.0"},
            "rule": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "kind": {"type": "string", "enum": ["taint", "pattern", "hybrid", "value"]},
                    "severity": {"type": "string", "enum": ["info", "warning", "error", "critical"]},
                    "message": {"type": "string"}
                },
                "required": ["id", "kind", "severity", "message"]
            },
            "scope": {
                "type": "object",
                "properties": {
                    "languages": {"type": "array", "items": {"type": "string"}},
                    "frameworks": {"type": "array", "items": {"type": "string"}},
                    "env": {
                        "type": "object",
                        "properties": {
                            "os": {"type": "array", "items": {"type": "string"}},
                            "shell": {"type": "array", "items": {"type": "string"}}
                        }
                    }
                },
                "required": ["languages", "frameworks"]
            },
            "sources": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "match": {"type": "object"}
                    },
                    "required": ["id", "match"]
                }
            },
            "sinks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "match": {"type": "object"}
                    },
                    "required": ["id", "match"]
                }
            },
            "sanitizers": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "match": {"type": "object"},
                        "effect": {"type": "string"}
                    },
                    "required": ["id", "match", "effect"]
                }
            },
            "barriers": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "match": {"type": "object"},
                        "effect": {"type": "string"}
                    },
                    "required": ["id", "match", "effect"]
                }
            },
            "propagations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "edge": {"type": "string"},
                        "kind": {"type": "string"}
                    },
                    "required": ["id", "edge", "kind"]
                }
            },
            "flows": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "source": {"type": "string"},
                        "sink": {"type": "string"},
                        "through": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["source", "sink", "through"]
                }
            },
            "report": {
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                    "locations": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["message", "locations"]
            },
            "tests": {
                "type": "object",
                "properties": {
                    "positive": {"type": "array", "items": {"type": "string"}},
                    "negative": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["positive", "negative"]
            }
        },
        "required": ["rule", "scope", "report", "tests"]
    }

    @staticmethod
    def validate(ir: XCPGIR) -> bool:
        """验证XCPG-IR对象是否符合规范"""
        try:
            # 将dataclass转换为字典
            ir_dict = XCPGIRValidator.to_dict(ir)
            # 使用jsonschema验证
            validate(instance=ir_dict, schema=XCPGIRValidator.SCHEMA)
            return True
        except Exception as e:
            print(f"XCPG-IR validation error: {str(e)}")
            return False

    @staticmethod
    def to_dict(obj: Any) -> dict:
        """将dataclass对象转换为字典"""
        if is_dataclass(obj) and not isinstance(obj, type):
            return {k: XCPGIRValidator.to_dict(v) for k, v in asdict(obj).items()}
        elif isinstance(obj, list):
            return [XCPGIRValidator.to_dict(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: XCPGIRValidator.to_dict(v) for k, v in obj.items()}
        return obj

    @staticmethod
    def to_json(ir: XCPGIR, indent: Optional[int] = 2) -> str:
        """将XCPG-IR对象转换为JSON字符串"""
        ir_dict = XCPGIRValidator.to_dict(ir)
        return json.dumps(ir_dict, indent=indent, ensure_ascii=False)

    @staticmethod
    def from_dict(ir_dict: dict) -> XCPGIR:
        """从字典创建XCPG-IR对象"""
        # 这里需要实现从字典到dataclass的转换
        # 为简化起见，这里只是示例框架
        # 实际实现需要递归处理嵌套对象
        from .flow import RuleMetadata, Scope, Report, TestCases
        from .entities import Source, Sink, Sanitizer, Barrier, Propagation
        
        # 简化处理，实际应递归处理嵌套对象
        rule = RuleMetadata(**ir_dict["rule"])
        scope = Scope(**ir_dict["scope"])
        report = Report(**ir_dict["report"])
        tests = TestCases(**ir_dict["tests"])
        
        return XCPGIR(
            xcpgir_version=ir_dict.get("xcpgir_version", "1.0"),
            rule=rule,
            scope=scope,
            sources=ir_dict.get("sources", []),
            sinks=ir_dict.get("sinks", []),
            sanitizers=ir_dict.get("sanitizers", []),
            barriers=ir_dict.get("barriers", []),
            propagations=ir_dict.get("propagations", []),
            flows=ir_dict.get("flows", []),
            report=report,
            tests=tests
        )