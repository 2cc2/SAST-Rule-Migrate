/**
 * @name Expression Language Injection
 * @description An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind path-problem
 * @problem.severity warning
 * @id java/el-injection
 * @tags security
 *       external/cwe/cwe-094
 *       owasp-a3
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.El

class DynamicInput extends UntrustedFlowSource::Range {
  DynamicInput() {
    exists(Method m, Parameter p | 
      p = m.getAParameter() and
      not p.getAnAccess().getValue().toString().matches("\".*\"")
    )
  }
}

class ElInjectionConfig extends TaintTracking::Configuration {
  ElInjectionConfig() { this = "ElInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof DynamicInput
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      (ma.getMethod().hasQualifiedName("javax.el.ExpressionFactory", "createValueExpression") and
      ma.getArgument(1) = sink.asExpr()) or
      (ma.getMethod().hasQualifiedName("javax.el.ExpressionFactory", "createMethodExpression") and
      ma.getArgument(1) = sink.asExpr()) or
      (ma.getMethod().getName() = "buildConstraintViolationWithTemplate" and
      ma.getArgument(0) = sink.asExpr())
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() instanceof StringLiteral
  }
}

from ElInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential EL injection vulnerability from unverified input"