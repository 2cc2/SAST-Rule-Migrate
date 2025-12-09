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
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.Expr
import semmle.code.java.Member

class SpELConfig extends TaintTracking::Configuration {
  SpELConfig() { this = "SpEL Injection Configuration" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodCall mc |
      mc.getMethod().getName() = "parseExpression" and
      (
        mc.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") or
        mc.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser") or
        mc.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser")
      ) and
      source.asExpr() = mc.getArgument(0)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().getName() = "parseExpression" and
      (
        mc.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") or
        mc.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser") or
        mc.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser")
      ) and
      sink.asExpr() = mc.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(StringLiteral sl | sl = node.asExpr())
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, SpELConfig config
where config.hasFlowPath(source, sink)
select sink, "A Spring expression is built with a dynamic value. The source of the value(s) " +
  "should be verified to avoid that unfiltered values fall into this risky code evaluation.",
  source, "User input"