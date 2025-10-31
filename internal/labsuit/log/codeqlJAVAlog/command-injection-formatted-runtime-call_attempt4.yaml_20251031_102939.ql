/**
 * @name Command Injection via Runtime.exec()
 * @description Detects potentially dangerous formatted or concatenated strings passed to Runtime.exec().
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id java/command-injection-formatted-runtime-call
 * @tags security
 *       cwe/78
 *       owasp-a1
 *       owasp-a3
 */

import java
import codeql.java.security.TaintTracking
import codeql.java.StringFormat
import codeql.java.dataflow.DataFlow
import DataFlow::PathGraph

class RuntimeExecConfig extends TaintTracking::Config {
  RuntimeExecConfig() { this = "RuntimeExecConfig" }

  override predicate isSource(TaintTracking::SourceNode source) {
    exists(LocalScopeVariable v |
      source.asExpr() = v.getAnAccess() and
      not v.getAnAccess().getValue().isCompileTimeConstant()
    )
  }

  override predicate isSink(TaintTracking::SinkNode sink) {
    exists(MethodAccess call |
      call.getMethod().getName() = ["exec", "loadLibrary"] and
      call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      (
        sink.asExpr() = call.getArgument(0) or
        sink.asExpr() = call.getArgument(1) or
        sink.asExpr() = call.getArgument(2)
      )
    )
  }

  override predicate isSanitizer(TaintTracking::Sanitizer sanitizer) {
    exists(Literal lit | sanitizer.asExpr() = lit)
  }

  override predicate isAdditionalTaintStep(TaintTracking::Taintable step1, TaintTracking::Taintable step2) {
    // Handle string concatenation
    exists(BinaryExpr b |
      b.getOp() = BinaryExpr.PLUS and
      (
        (step1.asExpr() = b.getLeftOperand() and step2.asExpr() = b) or
        (step1.asExpr() = b.getRightOperand() and step2.asExpr() = b)
      )
    )
    or
    // Handle string formatting
    exists(DataFlow::Node src, DataFlow::Node sink |
      DataFlow::localFlow(src, sink) and
      exists(MethodAccess formatCall |
        formatCall.getMethod().getName().matches("%s") and
        src.asExpr() = formatCall.getAnArgument() and
        sink.asExpr().getEnclosingCall() = formatCall
      )
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, RuntimeExecConfig conf
where conf.hasFlowPath(source, sink)
select sink, 
  "A formatted or concatenated string was detected as input to a java.lang.Runtime call. " +
  "This could result in command injection if the input is user-controlled.", 
  source, sink,
  "Ensure variables passed to Runtime.exec() are not user-controlled or properly sanitized."