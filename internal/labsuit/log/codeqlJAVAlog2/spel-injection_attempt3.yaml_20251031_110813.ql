/**
 * @name SpEL Injection
 * @description Detects Spring Expression Language injections where user input flows into expression evaluation
 * @kind path-problem
 * @id java/spel-injection
 * @tags security
 *       external/cwe/cwe-094
 * @severity Warning
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.Method

class SpELConfig extends TaintTracking::Configuration {
  SpELConfig() { this = "SpEL Injection Configuration" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "parseExpression" and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") and
      source.asExpr() = ma.getArgument(0)
      or
      ma.getMethod().getName() = "parseExpression" and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser") and
      source.asExpr() = ma.getArgument(0)
      or
      ma.getMethod().getName() = "parseExpression" and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser") and
      source.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "parseExpression" and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser") or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser")
      ) and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(Literal literal |
      literal = node.asExpr() and
      literal.getStringValue().matches("\".*\"")
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, SpELConfig config
where config.hasFlowPath(source, sink)
select sink, "A Spring expression is built with a dynamic value. The source of the value(s) " +
  "should be verified to avoid that unfiltered values fall into this risky code evaluation.",
  source, "User input"