/** 
 * @name Spring Expression Language (SpEL) Injection
 * @description A Spring expression is built with a dynamic value. The source of the value(s) 
 *              should be verified to avoid that unfiltered values fall into this risky code 
 *              evaluation.
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id java/spel-injection
 * @tags security
 *       spring
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.spring.SpringFrameworks
import DataFlow::PathGraph

class SpELExpressionSource extends MethodAccess {
  SpELExpressionSource() {
    this.getMethod().hasName("parseExpression") and
    (
      this.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") or
      this.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser") or
      this.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser")
    )
  }
}

class SpELSink extends MethodAccess {
  SpELSink() {
    this.getMethod().hasName("parseExpression") and
    (
      this.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") or
      this.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression.spel", "SpelExpressionParser") or
      this.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "TemplateAwareExpressionParser")
    )
  }

  int getSinkArg() { result = 0 }
}

class SpELSafeLiteral extends Literal {
  SpELSafeLiteral() {
    this instanceof StringLiteral and
    exists(this.getStringValue())
  }
}

class SpELTaintConfig extends TaintTracking::Configuration {
  SpELTaintConfig() { this = "SpELTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(SpELExpressionSource expr |
      source.asExpr() = expr.getArgument(0)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SpELSink call |
      sink.asExpr() = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(SpELSafeLiteral lit |
      sanitizer.asExpr() = lit
    )
  }
}

from SpELTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SpEL injection from $@", source.getNode(),
  "This user input reaches a Spring expression evaluation"