/**
 * @name EL Injection
 * @description An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation
 * @kind path-problem
 * @id java/el-injection
 * @severity Warning
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.frameworks.El
import DataFlow::PathGraph

class DynamicInput extends Parameter {
  DynamicInput() {
    exists(Method m | m = this.getAnAccess().getEnclosingCallable() |
      not this.getType().hasName("StringLiteral") and
      this.getValue().regexpMatch("[^\"]+")
    )
  }
}

class ElInjectionConfig extends TaintTracking::Configuration {
  ElInjectionConfig() { this = "ElInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asParameter() instanceof DynamicInput
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "createValueExpression" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
      sink.asExpr() = ma.getArgument(1)
    ) or
    exists(MethodAccess ma |
      ma.getMethod().getName() = "createMethodExpression" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
      sink.asExpr() = ma.getArgument(1)
    ) or
    exists(MethodAccess ma |
      ma.getMethod().getName() = "buildConstraintViolationWithTemplate" and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(StringLiteral sl |
      sl.getValue() = "\"\"" and
      sanitizer.asExpr() = sl
    )
  }
}

from ElInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink,
  "An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."