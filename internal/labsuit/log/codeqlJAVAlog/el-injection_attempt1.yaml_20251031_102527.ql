/**
 * @name Expression Language Injection
 * @id el-injection
 * @description An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       cwe: "CWE-94: Improper Control of Generation of Code ('Code Injection')"
 *       owasp: "A03:2021 - Injection"
 * @id-type strings
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.EL

class DynamicInput extends DataFlow::Node {
  DynamicInput() {
    exists(MethodParameter p |
      this.asParameter() = p and
      p.getType() instanceof TypeString and
      not p.getAnAssignedLiteral().getText() = "\"\""
    )
  }
}

class ELInjectionConfig extends TaintTracking::Configuration {
  ELInjectionConfig() { this = "ELInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof DynamicInput
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      (
        ma.getMethod().getName() = "createValueExpression" and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
        sink.asExpr() = ma.getArgument(1)
      )
      or
      (
        ma.getMethod().getName() = "createMethodExpression" and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
        sink.asExpr() = ma.getArgument(1)
      )
      or
      (
        ma.getMethod().getName() = "buildConstraintViolationWithTemplate" and
        sink.asExpr() = ma.getArgument(0)
      )
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(StringLiteral sl |
      sl.getValueText() = "" and
      sanitizer.asExpr() = sl
    )
  }
}

from ELInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink,
  "Expression Language injection vulnerability due to untrusted dynamic input."