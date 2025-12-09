/**
 * @name SpEL Injection
 * @description A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind path-problem
 * @problem.severity warning
 * @id java/spel-injection
 * @tags security
 *       spring
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class SpELInjectionConfig extends TaintTracking::Configuration {
  SpELInjectionConfig() { this = "SpELInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") and
       ma.getMethod().getName() = "parseExpression" and
       source.asExpr() = ma.getArgument(0)) or
      (ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser") and
       ma.getMethod().getName() = "parseExpression" and
       source.asExpr() = ma.getArgument(0)) or
      (ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser") and
       ma.getMethod().getName() = "parseExpression" and
       source.asExpr() = ma.getArgument(0))
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ((ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser") or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser")) and
       ma.getMethod().getName() = "parseExpression" and
       sink.asExpr() = ma.getArgument(0))
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() instanceof Literal
  }
}

from SpELInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SpEL injection vulnerability"