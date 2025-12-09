/**
 * @name Command injection via Runtime.exec()
 * @description Detects unsafe execution of commands constructed from user input
 * @kind path-problem
 * @problem.severity error
 * @id java/command-injection-formatted-runtime-call
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 *       owasp-a1
 *       owasp-a3
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import semmle.code.java.dataflow.DataFlow
import DataFlow::PathGraph

class RuntimeConfig extends TaintTracking::Configuration {
  RuntimeConfig() { this = "RuntimeCommandInjection" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m | 
      (m.hasName("getParameter") or m.hasName("getQueryString") or m.hasName("getHeader")) and
      source.asParameter() = m.getAParameter()
    )
    or
    exists(LocalVariableDecl lvd | 
      source.asExpr() = lvd.getInitializer() and
      not lvd.getInitializer().isConstant()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      (ma.getMethod().hasName("exec") or ma.getMethod().hasName("loadLibrary")) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      (sink.asExpr() = ma.getArgument(0) or sink.asExpr() = ma.getArgument(1) or sink.asExpr() = ma.getArgument(2))
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asConstant().isStringLiteral() or
    exists(StringLiteral sl | sanitizer.asExpr() = sl)
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(StringConcatExpr sce |
      pred.asExpr() = sce.getAnOperand() and
      succ.asExpr() = sce
    )
    or
    exists(FormatOperation fo |
      pred.asExpr() = fo.getAnOperand() and
      succ.asExpr() = fo
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, RuntimeConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "A formatted or concatenated string was detected as input to a java.lang.Runtime call. " +
  "This could result in command injection if user input is not properly sanitized."