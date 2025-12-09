/**
 * @id spel-injection
 * @severity WARNING
 * @name Spring Expression Language Injection
 * @description A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @tags spring
 * @tags java
 * @kind path-problem
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class SpELInjectionConfig extends TaintTracking::Configuration {
  SpELInjectionConfig() { this = "SpELInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      (
        (ma.getMethod().getName() = "parseExpression" and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser")) or
        (ma.getMethod().getName() = "parseExpression" and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser")) or
        (ma.getMethod().getName() = "parseExpression" and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser"))
      ) and
      source.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      (
        (ma.getMethod().getName() = "parseExpression" and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser")) or
        (ma.getMethod().getName() = "parseExpression" and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser")) or
        (ma.getMethod().getName() = "parseExpression" and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser"))
      ) and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Literal l |
      l = sanitizer.asExpr() and
      l.getStringValue() = "..."
    )
  }
}

from SpELInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."