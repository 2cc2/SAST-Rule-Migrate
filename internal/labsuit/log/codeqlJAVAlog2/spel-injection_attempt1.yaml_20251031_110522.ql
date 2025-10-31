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
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Spring

class SpELConfig extends TaintTracking::Configuration {
  SpELConfig() { this = "SpELInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess exprParser |
      (
        exprParser.getMethod().hasName("parseExpression") and
        (
          exprParser.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") or
          exprParser.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser") or
          exprParser.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser")
        ) and
        source.asExpr() = exprParser.getArgument(0)
      )
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess exprParser |
      (
        exprParser.getMethod().hasName("parseExpression") and
        (
          exprParser.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") or
          exprParser.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser") or
          exprParser.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser")
        ) and
        sink.asExpr() = exprParser.getArgument(0)
      )
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(Literal literal |
      node.asExpr() = literal and
      literal.getStringValue().regexpMatch("\"...\"")
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma, Parameter p, int argIdx |
      node1.asExpr() = ma.getArgument(argIdx) and
      node2.asParameter() = p and
      p = ma.getMethod().getParameter(argIdx)
    )
  }
}

from SpELConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SpEL injection vulnerability from $@", source.getNode(),
  "user input"