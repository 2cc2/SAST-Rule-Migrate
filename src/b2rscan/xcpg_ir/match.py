from dataclasses import dataclass
from typing import List, Optional, Union
from .types import NodeKind, MatchOperator

@dataclass
class ApiSignature:
    package: Optional[str] = None
    type: Optional[str] = None
    method: Optional[str] = None
    signature: Optional[List[str]] = None

@dataclass
class TypeMatch:
    name: Optional[str] = None
    match: Optional[str] = None  # "exact" or "subtype"

@dataclass
class WhereClause:
    op: MatchOperator
    left: str
    right: Union[str, int, float, bool, List[str]]

@dataclass
class Match:
    node: NodeKind
    api: Optional[ApiSignature] = None
    type: Optional[TypeMatch] = None
    arg_index: Optional[int] = None
    where: Optional[List[WhereClause]] = None