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
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.security.QueryInjection

class UserControlledInput extends RemoteFlowSource {
  UserControlledInput() {
    exists(Parameter p | this.asParameter() = p) or
    exists(LocalVariableDecl l | this.asLocalVariableDecl() = l)
  }
}

class RuntimeExecSink extends MethodAccess {
  RuntimeExecSink() {
    exists(Method m | 
      m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      (m.hasName("exec") or m.hasName("loadLibrary")) and
      this.getMethod() = m
    )
  }
}

class StringConcatOperation extends AddExpr {
  StringConcatOperation() {
    this.getRightOperand().getType() instanceof TypeString and
    this.getLeftOperand().getType() instanceof TypeString
  }
}

class FormatStringOperation extends MethodAccess {
  FormatStringOperation() {
    this.getMethod().hasName("format") and
    this.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("java.lang", "String")
  }
}

class LiteralSanitizer extends Literal {
  LiteralSanitizer() { 
    this.getValue().toString().matches("[^%\\\\]+")
  }
}

module TaintConfig implements TaintTracking::Config {
  override predicate isSource(DataFlow::Node source) {
    source instanceof UserControlledInput
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof RuntimeExecSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(StringConcatOperation concat |     
      concat = node1.asExpr() and
      (concat.getAnOperand() = node2.asExpr())
    ) or
    exists(FormatStringOperation formatOp |
      formatOp = node1.asExpr() and
      (formatOp.getAnArgument() = node2.asExpr())
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() instanceof LiteralSanitizer
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where TaintConfig::flowPath(source, sink)
select sink.getNode(), source, sink, "Formatted or concatenated string used in $@ may lead to command injection",
  source.getNode(), "user input",
  sink.getNode(), "Runtime.exec call"