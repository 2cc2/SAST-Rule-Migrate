from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union
from .types import RuleKind, SeverityLevel

@dataclass
class PathConstraint:
    pattern: str

@dataclass
class FlowConstraints:
    path: Optional[Dict[str, List[PathConstraint]]] = None

@dataclass
class Flow:
    source: str
    sink: str
    through: List[str]
    constraints: Optional[FlowConstraints] = None

@dataclass
class EvidenceCapture:
    argument: Optional[int] = None
    variable: Optional[str] = None

@dataclass
class Report:
    message: str
    locations: List[str]
    evidence: Optional[Dict[str, List[EvidenceCapture]]] = None

@dataclass
class TestCases:
    positive: List[str]
    negative: List[str]

@dataclass
class Environment:
    os: List[str] = field(default_factory=lambda: ["linux", "windows"])
    shell: List[str] = field(default_factory=lambda: ["bash", "sh", "powershell"])

@dataclass
class Scope:
    languages: List[str] = field(default_factory=lambda: ["java", "python", "go", "js", "php"])
    frameworks: List[str] = field(default_factory=lambda: ["*"])
    env: Optional[Environment] = None

@dataclass
class RuleMetadata:
    id: str
    kind: RuleKind
    severity: SeverityLevel
    message: str