from enum import Enum

class RuleKind(str, Enum):
    TAINT = "taint"
    PATTERN = "pattern"
    HYBRID = "hybrid"
    VALUE = "value"

class SeverityLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class NodeKind(str, Enum):
    FILE = "FILE"
    NAMESPACE_BLOCK = "NAMESPACE_BLOCK"
    TYPE_DECL = "TYPE_DECL"
    METHOD = "METHOD"
    BLOCK = "BLOCK"
    METHOD_PARAMETER_IN = "METHOD_PARAMETER_IN"
    METHOD_RETURN = "METHOD_RETURN"
    LOCAL = "LOCAL"
    MEMBER = "MEMBER"
    CALL = "CALL"
    IDENTIFIER = "IDENTIFIER"
    LITERAL = "LITERAL"
    FIELD_IDENTIFIER = "FIELD_IDENTIFIER"
    ASSIGNMENT = "ASSIGNMENT"
    RETURN = "RETURN"
    CONTROL_STRUCTURE = "CONTROL_STRUCTURE"
    JUMP_TARGET = "JUMP_TARGET"
    TYPE = "TYPE"
    TYPE_ARGUMENT = "TYPE_ARGUMENT"
    IMPORT = "IMPORT"
    PACKAGE = "PACKAGE"

class MatchOperator(str, Enum):
    EQ = "eq"
    NEQ = "neq"
    REGEX = "regex"
    IN = "in"

class SanitizerEffect(str, Enum):
    NEUTRALIZE = "neutralize"
    REMOVE_ADD = "remove_add"
    TRANSFORM = "transform"

class BarrierEffect(str, Enum):
    STOP = "stop"
    FILTER = "filter"