/**
 * @name EL Injection
 * @description An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @problem.severity warning
 * @id java/el-injection
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

private class DynamicInput extends DataFlow::Node {
  DynamicInput() {
    exists(Parameter p | 
      this.asParameter() = p and
      not this.asExpr().(StringLiteral).getValue() = ""
    ) or
    exists(LocalVariableDecl lvd |
      this.asExpr() = lvd.getInitializer() and
      not this.asExpr().(StringLiteral).getValue() = ""
    )
  }
}

private class ExpressionFactorySink extends DataFlow::Node {
  ExpressionFactorySink() {
    exists(MethodCall mc |
      (mc.getMethod().getName() = "createValueExpression" and
       mc.getMethod().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
       this.asExpr() = mc.getArgument(1))
      or
      (mc.getMethod().getName() = "createMethodExpression" and
       mc.getMethod().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
       this.asExpr() = mc.getArgument(1))
      or
      (mc.getMethod().getName() = "buildConstraintViolationWithTemplate" and
       this.asExpr() = mc.getArgument(0))
    )
  }
}

private class Sanitizer extends DataFlow::Node {
  Sanitizer() {
    this.asExpr() instanceof StringLiteral
  }
}

from DataFlow::Node source, DataFlow::Node sink
where DataFlow::localFlow(source, sink) and
      source instanceof DynamicInput and
      sink instanceof ExpressionFactorySink and
      not exists(DataFlow::Node sanitizer |
                  sanitizer instanceof Sanitizer and
                  DataFlow::localFlow(source, sanitizer) and
                  DataFlow::localFlow(sanitizer, sink)
               )
select sink, "Potential EL injection detected from $@", source, source.toString()