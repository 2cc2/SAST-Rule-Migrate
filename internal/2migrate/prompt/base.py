from abc import ABC, abstractmethod

class PromptTemplate(ABC):
    @abstractmethod
    def format(self, **kwargs) -> str:
        pass

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
example= """
            /**
 * @name Tainted command from HTTP request
 * @description Detected input from a HTTPServletRequest going into a 'ProcessBuilder' or 'exec' command.
 *              This could lead to command injection if variables passed into the exec commands are not properly sanitized.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id java/tainted-cmd-from-http-request
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Servlets

class HttpRequestSource extends DataFlow::Node {
  HttpRequestSource() { 
    exists(MethodAccess ma | ma.getMethod().getName() = "getParameter" and
      ma.getQualifier().getType().hasName(["javax.servlet.http.HttpServletRequest"])
    ) or
    exists(MethodAccess ma | ma.getMethod().getName() = "getValue" and
      ma.getQualifier().getType().hasName(["javax.servlet.http.Cookie"])
    )
  }
}

class CommandExecutionSink extends DataFlow::Node {
  CommandExecutionSink() {
    exists(ConstructorCall cc | cc.getConstructedType().hasName("java.lang.ProcessBuilder") and
      this.asExpr() = cc.getArgument(0)
    ) or
    exists(MethodCall mc | mc.getMethod().hasName("exec") and 
      mc.getMethod().getDeclaringType().hasName("java.lang.Runtime") and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

class TaintedCommandFlowConfig extends TaintTracking::Configuration {
  TaintedCommandFlowConfig() { this = "TaintedCommandFromHttp" }

  override predicate isSource(DataFlow::Node source) { source instanceof HttpRequestSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof CommandExecutionSink }
}

from TaintedCommandFlowConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "User input from HTTP request reaches OS command execution", source.getNode(), 
  "This user input comes from an HTTP request"
"""