/**
 * @name Tainted SQL string
 * @description User data flows into this manually-constructed SQL string. Use prepared statements instead.
 * @kind problem
 * @id java/tainted-sql-string
 * @security-severity 8.8
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class UserInputParameter extends MethodParameter {
  UserInputParameter() {
    exists(Type t | this.getType() = t |
      not t.hasName(["Integer", "Long", "Float", "Double", "Char", "Boolean",
                    "int", "long", "float", "double", "char", "boolean"]) and
      exists(Annotation a |
        a.getType().hasQualifiedName(["javax.servlet", "org.springframework.web.bind.annotation"],
                                    ["RequestBody", "PathVariable", "RequestParam", "RequestHeader", "CookieValue"]) and
        a = this.getAnAnnotation()
      )
    )
  }
}

class StringConcatenation extends MethodAccess {
  StringConcatenation() {
    this.getMethod().hasName(["concat", "append", "format"]) and
    this.getQualifier().getType().hasName("String") and
    this.getArgument(0).toString().matches(/select|delete|insert|create|update|alter|drop/i) and
    not this.getMethod().getDeclaringType().hasQualifiedName(["java.lang.System", "org.slf4j.Logger"],
                                                           ["out", "LOG"])
  }
}

class TaintedSQLConfig extends TaintTracking::Configuration {
  TaintedSQLConfig() { this = "TaintedSQLConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asParameter() instanceof UserInputParameter
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(StringConcatenation sc | sink.asExpr() = sc)
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedSQLConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), "User data flows into this manually-constructed SQL string. Use prepared statements instead.",
  source.getNode(), "User input source"