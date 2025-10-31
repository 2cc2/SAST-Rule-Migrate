/**
 * @name SpEL Injection
 * @description A Spring expression is built with a dynamic value. The source of the value(s) 
 *              should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @id java/spring/spel-injection
 * @tags security
 *       spring
 * @severity warning
 */

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class SpELParserCall extends MethodAccess {
  SpELParserCall() {
    this.getMethod().hasQualifiedName("org.springframework.expression", "ExpressionParser", "parseExpression") or
    this.getMethod().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser", "parseExpression") or
    this.getMethod().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser", "parseExpression")
  }
}

class SpELInjectionConfig extends TaintTracking::Configuration {
  SpELInjectionConfig() { this = "SpELInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(SpELParserCall call |
      call.getArgument(0) = source.asExpr() and
      call.getMethod().hasQualifiedName("org.springframework.expression", "ExpressionParser", "parseExpression") or
      call.getMethod().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser", "parseExpression") or
      call.getMethod().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser", "parseExpression")
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SpELParserCall call |
      call.getArgument(0) = sink.asExpr() and
      call.getMethod().hasQualifiedName("org.springframework.expression", "ExpressionParser", "parseExpression") or
      call.getMethod().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser", "parseExpression") or
      call.getMethod().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser", "parseExpression")
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(string literalValue |
      node.asExpr() instanceof StringLiteral and
      literalValue = node.asExpr().(StringLiteral).getValue()
    )
  }
}

from SpELInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This Spring Expression Language (SpEL) evaluation uses user-provided input."