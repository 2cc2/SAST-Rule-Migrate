from dataclasses import dataclass, field
from typing import List
from .flow import RuleMetadata, Scope, Flow, Report, TestCases
from .entities import Source, Sink, Sanitizer, Barrier, Propagation

@dataclass
class XCPGIR:
    rule: RuleMetadata
    scope: Scope
    report: Report
    tests: TestCases
    xcpgir_version: str = "1.0"
    sources: List[Source] = field(default_factory=list)
    sinks: List[Sink] = field(default_factory=list)
    sanitizers: List[Sanitizer] = field(default_factory=list)
    barriers: List[Barrier] = field(default_factory=list)
    propagations: List[Propagation] = field(default_factory=list)
    flows: List[Flow] = field(default_factory=list)