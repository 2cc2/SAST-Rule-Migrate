from .base import PromptTemplate

Doc_content = """
以下是目标中间表示的规范文档：
# 📑 XCPG-IR 规范 v1.0
*(eXtended Code Property Graph Intermediate Representation)*
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
👉 **XCPG-IR 的目标**：
- 基于 **CPG (Code Property Graph)** 统一抽象；
- 表达 **污点传播、值检查、API misuse**；
- 支持跨语言、跨引擎的规则迁移与共享。
------
## 2. 什么是 CPG
**CPG = AST + CFG + DFG 的融合图**。
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
👉 **意义**：
- Source/Sink 对应 **CPG 节点**；
- 传播 Propagation 对应 **CPG 边**；
- Flow 约束对应 **路径模式 (CFG+DFG)**。
------
## 3. 什么是 XCPG
**XCPG = eXtended CPG**，在原始 CPG 的基础上扩展：
- 引入 **跨语言统一 API 签名**；
- 定义 **污点标签体系 (taint kinds)**；
- 明确 **Sanitizer（净化）与 Barrier（阻断）**；
- 增加 **Flow constraints**（must/must_not）用于复杂路径约束；
- 提供可迁移到 **CodeQL / Semgrep / PMD / GoSec** 的抽象层。
------
## 4. XCPG-IR 结构
```yaml
xcpgir_version: "1.0"
rule:
  id: string
  kind: taint | pattern | hybrid | value
  severity: INFO | WARNING | ERROR | CRITICAL
  message: string
scope:
  languages: [java, python, go, js, php, "*"]
  frameworks: ["*"]
  env: { os: [linux, windows], shell: [bash, sh, powershell] }
sources: [...]
sinks: [...]
sanitizers: [...]
barriers: [...]
propagations: [...]
flows: [...]
report: {...}
tests: {...}
```
------
## 5. Match（节点匹配）
所有实体（Source / Sink / Sanitizer / Barrier）都通过 **match** 来定位 CPG 节点。
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
### Barrier
```yaml
barriers:
  - id: RETURN_STOP
    match: { node: RETURN }
    effect: stop
```
### Propagation
```yaml
propagations:
  - id: ARG_TO_PARAM
    edge: arg->param | return | field-store | field-load | array | phi | alias
    kind: taint | value
```
------
## 7. Flow（源到汇路径）
Flow 定义了可能的数据流轨迹，Barrier 在执行时自动剪枝。【这个flow这使用的ID】
```yaml
flows:
  - source: USER_INPUT
    sink: SQL_EXEC
    through: [ARG_TO_PARAM*, RETURN*]
    constraints:
      path:
        must:     [ { pattern: "CALL(java.sql.Statement.executeQuery)" } ]
        must_not: [ { pattern: "CALL(org.owasp.ESAPI.encoder.encodeForSQL)" } ]
```
------
## 8. Sanitizer vs Barrier
| 属性       | Sanitizer                           | Barrier                            |
| ---------- | ----------------------------------- | ---------------------------------- |
| 语义       | 转换 / 净化污点                     | 完全阻断传播                       |
| 结果       | 数据继续流动，但标签改变            | 数据流在此终止                     |
| 示例       | `escapeHtml()`, `Path.toRealPath()` | `return`, `throw`, `System.exit()` |
| 对路径搜索 | 保留边但修改标签                    | 剪枝，路径不再延伸                 |
------
## 9. Report 与 Tests
```yaml
report:
  message: "User input reaches SQL execution without sanitization"
  locations: ["source","sink","path"]
  evidence: { capture: [{ argument: 0 }] }
tests:
  positive:
    - "stmt.executeQuery(request.getParameter(\"q\"));"
  negative:
    - "stmt.executeQuery(ESAPI.encoder().encodeForSQL(request.getParameter(\"q\")));"
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

barriers:
  - id: RETURN_STOP
    match: { node: RETURN }
    effect: stop

flows:
  - source: REL_PATH_LITERAL
    sink: EXEC
    through: [ARG_PARAM*]
    constraints:
      path:
        must:     [ { pattern: "CALL(java.lang.Runtime.exec)" } ]
        must_not: [ { pattern: "CALL(java.io.File.isAbsolute)" } ]

report:
  locations: ["source","sink","path"]
  evidence: { capture: [{ argument: 0 }] }
```
"""
class BasePrompt(PromptTemplate):
    # def __init__(self, shared_context: str):
    #     self.shared_context = shared_context

    def format(self,code:str,specific_content: str) -> str:
        return f"""
<role>
你是一个静态分析规则的结构化抽取大师，熟悉Codeql工具的规则。
</role>
<task>
请根据输入的Codeql工具的Java类型规则内容，及提供的上下文内容，总结漏洞检测规则的中间表示用于规则迁移。
</task>
<input>
输入规则内容如下：
---
{code}
---
<input/>
<doc>
{Doc_content}
<doc/>
<example>
{example_content}
<example/>
<output>
{specific_content}
<output>
"""
    
class SourcePrompt(BasePrompt):
    def format(self,code) -> str:
        specific_content = """
请参照文档内容直接返回如下格式的yaml文件，只描述Source，不输出其他内容：
sources:
  - id: USER_INPUT
    match:
      node: CALL
      api: {{ type: javax.servlet.ServletRequest, method: getParameter }}
"""
        return super().format(code,specific_content)

class SinkPrompt(BasePrompt):
    def format(self,code) -> str:
        specific_content = """
```yaml
sinks:
  - id: SQL_EXEC
    match:
      node: CALL
      api: { type: java.sql.Statement, method: executeQuery }
      arg_index: 0
```
"""
        return super().format(code,specific_content)
class SanitazerPrompt(BasePrompt):
    def format(self,code) -> str:
        specific_content = """
```yaml
sanitizers:
  - id: ESCAPE_HTML
    match: { node: CALL, api: { type: org.apache.commons.lang.StringEscapeUtils, method: escapeHtml } }
    effect: neutralize
    scope: { sinks: [XSS_SINK] }
```
"""
        return super().format(code,specific_content)

class PropagationPrompt(BasePrompt):
    def format(self,code) -> str:
        specific_content = """
```yaml
propagations:
  - id: ARG_TO_PARAM
    edge: arg->param | return | field-store | field-load | array | phi | alias
    kind: taint | value
```
"""
        return super().format(code,specific_content)