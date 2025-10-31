/**
 * @name Command injection in formatted Runtime call
 * @description Detects formatted or concatenated strings used as input to java.lang.Runtime calls
 * @kind problem
 * @problem.severity error
 * @id java/command-injection-formatted-runtime-call
 * @tags security
 *       external/cwe/cwe-078
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import codeql.java.dataflow.TaintTracking
import codeql.java.StringFormat
import DataFlow::PathGraph

class RuntimeConfig extends TaintTracking::Configuration {
  RuntimeConfig() { this = "RuntimeCommandInjection" }

  override predicate isSource(DataFlow::Node source) {
    source.asParameter() or
    source.asLocalVariable() and not source.asLiteral()
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("exec") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      sink.asExpr() = ma.getArgument(0) or 
      sink.asExpr() = ma.getArgument(1) or
      sink.asExpr() = ma.getArgument(2)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("loadLibrary") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asLiteral()
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(StringConcatExpr sce | 
      pred.asExpr() = sce.getLeftOperand() and succ.asExpr() = sce.getRightOperand() or
      pred.asExpr() = sce.getRightOperand() and succ.asExpr() = sce.getLeftOperand()
    )
    or
    exists(FormattingOperation fo |
      succ.asExpr() = fo.getFormatted() and pred.asExpr() = fo.getOperand(_)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, RuntimeConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), 
  "A formatted or concatenated string was detected as input to a java.lang.Runtime call. " +
  "This could result in command injection if variables are user-controlled.", 
  source, sink