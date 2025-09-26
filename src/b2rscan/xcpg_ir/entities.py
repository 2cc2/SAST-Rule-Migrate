from dataclasses import dataclass
from typing import List, Optional
from .match import Match
from .types import SanitizerEffect, BarrierEffect

@dataclass
class Source:
    id: str
    match: Match

@dataclass
class Sink:
    id: str
    match: Match

@dataclass
class SanitizerEffectConfig:
    remove: Optional[List[str]] = None
    add: Optional[List[str]] = None

@dataclass
class SanitizerScope:
    sinks: Optional[List[str]] = None

@dataclass
class Sanitizer:
    id: str
    match: Match
    effect: SanitizerEffect
    scope: Optional[SanitizerScope] = None
    effect_config: Optional[SanitizerEffectConfig] = None

@dataclass
class Barrier:
    id: str
    match: Match
    effect: BarrierEffect

@dataclass
class Propagation:
    id: str
    edge: str  # 可以是EdgeKind或自定义路径
    kind: str  # "taint" | "value"