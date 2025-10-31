/**
 * @name Command injection via formatted Runtime call
 * @description Detects command injection when formatted/concatenated strings 
 *              are used in Runtime.exec() or loadLibrary() calls.
 * @kind taint
 * @problem.severity error
 * @id java/command-injection-formatted-runtime-call
 * @tags security
 *       external/cwe/cwe-078
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat

class RuntimeExecConfig extends TaintTracking::Configuration {
  RuntimeExecConfig() { this = "RuntimeExecTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p | source.asParameter() = p |
      not source instanceof Literal
    )
    or
    exists(LocalVariable v | source.asLocalVar() = v |
      not source instanceof Literal
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      (ma.getMethod().hasName("exec") or ma.getMethod().hasName("loadLibrary")) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      (
        sink.asExpr() = ma.getArgument(0) or
        sink.asExpr() = ma.getArgument(1) or
        sink.asExpr() = ma.getArgument(2)
      )
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof Literal
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Propagate through string concatenation
    exists(StringConcatExpr sce | 
      pred.asExpr() = sce.getAnOperand() and 
      succ.asExpr() = sce
    )
    or
    // Propagate through string formatting
    exists(FormattingOperation fo |
      pred.asExpr() = fo.getAnOperand() and
      succ.asExpr() = fo
    )
  }
}

from DataFlow::Node source, DataFlow::Node sink, RuntimeExecConfig config
where config.hasFlow(source, sink)
select sink, 
  "A formatted or concatenated string was detected as input to a Runtime call. " +
  "This could result in command injection. Ensure variables are properly sanitized.",
  source, "Untrusted input flows to command execution"