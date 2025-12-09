/**
 * @name Command injection via formatted string in Runtime.exec
 * @description Formatted or concatenated strings used as input to Runtime.exec can lead 
 *              to command injection if user-controlled variables are included.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/command-injection-formatted-runtime-call
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-089
 *       external/cwe/cwe-090
 *       external/cwe/cwe-091
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.StringUtil
import DataFlow::PathGraph

class UserControlledInput extends RemoteFlowSource {
  predicate isSource() { 
    exists(Parameter p | this = p) or
    exists(LocalVariableDecl l | this = l.getAChild*())
  }

  override string getSourceType() { result = "User controlled input" }
}

class RuntimeExecSink extends Expr {
  RuntimeExecSink() {
    exists(Method m | 
      m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      (m.hasName("exec") or m.hasName("loadLibrary")) and
      this.(Call).getCallee() = m
    )
  }
}

class TaintConfig extends TaintTracking::Configuration {
  TaintConfig() { this = "Command injection in Runtime.exec" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof UserControlledInput
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof RuntimeExecSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node src, DataFlow::Node sink) {
    exists(AddExpr concat |     
      concat = src.asExpr() and
      sink.asExpr() = concat.getAnOperand()
    ) or
    exists(Call formatOp |
      formatOp.getCallee().hasName("format") and
      formatOp.getDeclaringType().hasQualifiedName("java.lang", "String") and
      src.asExpr() = formatOp and
      sink.asExpr() = formatOp.getAnArgument()
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Literal lit | lit = sanitizer.asExpr() and lit.getValue().toString().matches("[^%\\\\]+"))
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintConfig conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Formatted or concatenated string used in $@ may lead to command injection",
  source.getNode(), "user input",
  sink.getNode(), "Runtime.exec call"