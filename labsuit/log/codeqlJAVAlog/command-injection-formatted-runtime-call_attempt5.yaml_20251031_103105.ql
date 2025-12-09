/**
 * @name Command injection via Runtime.exec()
 * @description Detects command injection vulnerabilities in formatted or concatenated strings
 *              passed to java.lang.Runtime.exec() or loadLibrary() calls.
 * @id command-injection-formatted-runtime-call
 * @kind problem
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-078
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import semmle.code.java.dataflow.DataFlow

class RuntimeExecConfig extends TaintTracking::Configuration {
  RuntimeExecConfig() { this = "RuntimeExecConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method method, Parameter param |
      source.asParameter() = param and
      param.getMethod() = method and
      not source instanceof Literal
    )
    or
    exists(LocalVariable var |
      source.asLocalVariable() = var and
      not source instanceof Literal
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "exec" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      (sink.asExpr() = ma.getArgument(0) or sink.asExpr() = ma.getArgument(1) or sink.asExpr() = ma.getArgument(2))
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().getName() = "loadLibrary" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof Literal
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(BinaryExpr expr |
      expr.getOperator() = BinaryOperator.PLUS and
      (pred.asExpr() = expr.getLeftOperand() and succ.asExpr() = expr) or
      (pred.asExpr() = expr.getRightOperand() and succ.asExpr() = expr)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("%format%") and
      pred.asExpr() = ma.getAnArgument() and
      succ.asExpr() = ma
    )
  }
}

from RuntimeExecConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "A formatted or concatenated string was detected as input to a java.lang.Runtime call. " +
  "This could result in command injection if the input is user-controlled."