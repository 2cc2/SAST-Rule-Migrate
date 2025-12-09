/**
 * @name SpEL Injection
 * @description A Spring expression is built with a dynamic value. The source of the value(s) should 
 *              be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @id java/spel-injection
 * @tags security
 *       spring
 * @severity Warning
 */

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class SpELParserCall extends MethodAccess {
  SpELParserCall() {
    getTarget().getName() = "parseExpression" and
    (
      getTarget().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") or
      getTarget().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser") or
      getTarget().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser")
    )
  }
}

class SpELExpressionSource extends SpELParserCall {
  SpELExpressionSource() { this.getArgument(0).getType() instanceof StringType }
}

class SpELSink extends SpELParserCall {
  SpELSink() { this.getArgument(0).getType() instanceof StringType }
}

class SpELSafeLiteral extends StringLiteral {
  SpELSafeLiteral() {
    this.getValue().regexpMatch("\\.\\.\\.") // Simplified regex for literal detection
  }
}

class SpELConfiguration extends TaintTracking::Configuration {
  SpELConfiguration() { this = "SpEL Injection Configuration" }

  override predicate isSource(DataFlow::Node source) {
    exists(SpELExpressionSource s |
      source.asExpr() = s.getArgument(0)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SpELSink s |
      sink.asExpr() = s.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(SpELSafeLiteral lit | sanitizer.asExpr() = lit)
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, SpELConfiguration config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Dynamic Spring Expression evaluation with potentially unsafe input: $@.", source.getNode(), 
  "User input"