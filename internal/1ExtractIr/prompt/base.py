from abc import ABC, abstractmethod

class PromptTemplate(ABC):
    @abstractmethod
    def format(self, **kwargs) -> str:
        pass

Motivation="""
------
## 1. 背景与动机
不同 SAST 工具（CodeQL、Semgrep、PMD、GoSec、Bandit 等）规则语言差异大：
- CodeQL → 强调数据流与路径。
- Semgrep → 偏向 AST pattern + 轻量 taint。
- PMD/FindSecBugs → 主要是 API misuse。
- GoSec/ESLint-security → 针对语言特性。
缺点：
- 规则不可复用；
- 无法统一 benchmark；
- 工业界和学术界交流困难。
👉 XCPG-IR 的目标：
- 基于 CPG (Code Property Graph) 统一抽象；
- 表达 污点传播、值检查、API misuse；
- 支持跨语言、跨引擎的规则迁移与共享。
------
"""
Doc_content = """
以下是目标中间表示的规范文档：
# XCPG-IR 规范 v1.0
## 1. 什么是 CPG
CPG = AST + CFG + DFG 的融合图。
 它是静态分析工具（如 Joern、CodeQL）的底层语义模型。
### 2.1 节点类型（Nodes）
| 类别     | Node Kind                                                    | 说明 |
| -------- | ------------------------------------------------------------ | ---- |
| 程序结构 | `FILE`, `NAMESPACE_BLOCK`, `TYPE_DECL`, `METHOD`, `BLOCK`    |      |
| 参数变量 | `METHOD_PARAMETER_IN`, `METHOD_RETURN`, `LOCAL`, `MEMBER`    |      |
| 表达式   | `CALL`, `IDENTIFIER`, `LITERAL`, `FIELD_IDENTIFIER`, `ASSIGNMENT`, `RETURN` |      |
| 控制流   | `CONTROL_STRUCTURE`, `JUMP_TARGET`                           |      |
| 类型系统 | `TYPE`, `TYPE_ARGUMENT`                                      |      |
| 模块化   | `IMPORT`, `PACKAGE`                                          |      |
### 2.2 边类型（Edges）
| 类别     | Edge Kind                             | 说明 |
| -------- | ------------------------------------- | ---- |
| 语法     | `AST`, `ARGUMENT`, `RECEIVER`         |      |
| 控制流   | `CFG`, `CDG`, `DOMINATE`              |      |
| 数据流   | `DFG`, `REACHING_DEF`, `PHI`, `ALIAS` |      |
| 调用图   | `CALL`, `REF`, `BINDS_TO`             |      |
| 类型关系 | `EVAL_TYPE`, `INHERITS_FROM`          |      |
| 特殊     | `CAPTURED_BY`（闭包捕获）             |      |
👉 意义：
- Source/Sink 对应 CPG 节点；
- 传播 Propagation 对应 CPG 边；
------
## 2. 什么是 XCPG
XCPG = eXtended CPG，在原始 CPG 的基础上扩展：
- 引入 跨语言统一 API 签名；
- 定义 污点标签体系 (taint kinds)；
- 明确 Sanitizer（净化）与 Barrier（阻断）；
- 增加 Flow constraints（must/must_not）用于复杂路径约束；
- 提供可迁移到 CodeQL / Semgrep / PMD / GoSec 的抽象层。
------
## 4. XCPG-IR 结构
```yaml
xcpgir_version: "1.0"
rule:
  id: string
  kind: taint | pattern | hybrid | value
  severity: INFO | WARNING | ERROR | CRITICAL
  message: string
sources: [...]
sinks: [...]
sanitizers: [...]
propagations: [...]
```
------
## 5. Match（节点匹配）
所有实体（Source / Sink / Sanitizer / Barrier）都通过 match 来定位 CPG 节点。
```yaml
match:
  node: CALL | LITERAL | PARAM | RETURN | FIELD | METHOD
  api:
    package: string
    type: string
    method: string
    signature: ["(...)"]
  type:
    name: string
    match: exact | subtype
  arg_index: int
  where:
    - op: eq | neq | regex | in
      left: 属性名 (value, methodFullName, arg[0].value)
      right: 值
```
------
## 6. 实体定义
### Source
```yaml
sources:
  - id: USER_INPUT
    match:
      node: CALL
      api: { type: javax.servlet.ServletRequest, method: getParameter }
```
### Sink
```yaml
sinks:
  - id: SQL_EXEC
    match:
      node: CALL
      api: { type: java.sql.Statement, method: executeQuery }
      arg_index: 0
```
### Sanitizer
```yaml
sanitizers:
  - id: ESCAPE_HTML
    match: { node: CALL, api: { type: org.apache.commons.lang.StringEscapeUtils, method: escapeHtml } }
    effect: neutralize
    scope: { sinks: [XSS_SINK] }
```
### Propagation
```yaml
propagations:
  - id: ARG_TO_PARAM
    edge: arg->param | return | field-store | field-load | array | phi | alias
    kind: taint | value
```
------
"""
example_content = """
```yaml
xcpgir_version: "1.0"
rule:
  id: java.relative-path-exec
  kind: taint
  severity: WARNING
  message: "Relative path command execution: ${sink.arg0.preview}"

sources:
  - id: REL_PATH_LITERAL
    match:
      node: LITERAL
      where:
        - op: regex
          left: value
          right: "^\\.|^\\.\\.|^\\./|^\\.\\./"

sinks:
  - id: EXEC
    match:
      node: CALL
      api: { type: java.lang.Runtime, method: exec }
      arg_index: 0

propagations:
  - id: ARG_PARAM
    edge: arg->param
    kind: taint

sanitizers:
  - id: TO_REAL_PATH
    match: { node: CALL, api: { type: java.nio.file.Path, method: toRealPath } }
    effect: { remove: ["path(relative)"], add: ["path(absolute)"] }
```
"""
specific_content ="""
```yaml 
<output>   
请参照文档内容直接返回如下格式的yaml文件，不输出其他内容,要求不漏不缺严格正确：
xcpgir_version: "1.0"  # XCPG-IR 的版本号
rule:
  id: string            # 规则的唯一标识符
  name: string          # 规则的名称（可选）
  kind:                 # 规则的类型
    - taint             # 污点分析规则
    - pattern           # 模式匹配规则
    - hybrid            # 混合规则
    - value             # 值分析规则
  severity:             # 规则的严重性级别
    - INFO              # 信息提示
    - WARNING           # 警告
    - ERROR             # 错误
    - CRITICAL          # 严重错误
  message: string       # 规则的描述信息
  tags:                 # 规则的标签（可选）
    - string            # 例如：语言、框架等
  metadata:             # 元信息（可选）
    language: string    # 适用的语言（如 Python、Java）
    category: string    # 规则分类（如 安全、性能）
  sources: [...]        # 定义规则的 Source 节点
  sinks: [...]          # 定义规则的 Sink 节点
  sanitizers: [...]     # 定义规则的 Sanitizer 节点
  propagations: [...]   # 定义规则的传播路径
</output>
"""