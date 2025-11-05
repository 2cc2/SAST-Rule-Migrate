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
import DataFlow::PathGraph

predicate isUserControlledInput(DataFlow::Node source) {
  exists(Parameter p | source.asParameter() = p) or
  exists(LocalVariableDecl l, VariableAccess va |
    source.asExpr() = va and
    va.getVariable() = l.getAVariable()
  )
}

predicate isRuntimeExecSink(DataFlow::Node sink) {
  exists(Method m, Call call |
    call = sink.asExpr() and
    call.getCallee() = m and
    m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
    (m.hasName("exec") or m.hasName("loadLibrary"))
  )
}

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "Command injection in Runtime.exec" }

  override predicate isSource(DataFlow::Node source) {
    isUserControlledInput(source)
  }

  override predicate isSink(DataFlow::Node sink) {
    isRuntimeExecSink(sink)
  }

  override predicate isAdditionalTaintStep(DataFlow::Node src, DataFlow::Node sink) {
    exists(AddExpr concat |
      concat = src.asExpr() and
      sink.asExpr() = concat.getAnOperand()
    )
    or
    exists(MethodAccess formatOp |
      formatOp.getMethod().hasName("format") and
      formatOp.getDeclaringType().hasQualifiedName("java.lang", "String") and
      src.asExpr() = formatOp and
      sink.asExpr() = formatOp.getAnArgument()
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() instanceof Literal
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, CommandInjectionConfig conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Formatted or concatenated string used in $@ may lead to command injection",
  source.getNode(), "user input",
  sink.getNode(), "Runtime.exec call"