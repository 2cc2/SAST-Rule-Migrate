/**
 * @name Command Injection via Formatted Runtime Call
 * @description A formatted or concatenated string detected as input to a java.lang.Runtime call.
 *              This could result in command injection if variables are user-controlled.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-078
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 * @id java/command-injection-formatted-runtime-call
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.DataFlow

class UserControlledInput extends DataFlow::Node {
  UserControlledInput() {
    exists(MethodParam p | 
      this.asParameter() = p and
      not p.getAnAssignment().getExpr() instanceof Literal
    )
    or
    exists(LocalVariableDecl l |
      this.asLocalVar() = l and
      not l.getInitializer() instanceof Literal
    )
  }
}

class RuntimeExecSink extends DataFlow::Node {
  RuntimeExecSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("exec") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      (ma.getArgument(0) = this.asExpr() or
       ma.getArgument(1) = this.asExpr() or
       ma.getArgument(2) = this.asExpr())
    )
  }
}

class RuntimeLoadLibrarySink extends DataFlow::Node {
  RuntimeLoadLibrarySink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("loadLibrary") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      ma.getArgument(0) = this.asExpr()
    )
  }
}

literalSanitizer(Sanitizer sanitizer) {
  exists(Literal l | sanitizer.hasFlowNode(l))
}

module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof UserControlledInput }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof RuntimeExecSink or
    sink instanceof RuntimeLoadLibrarySink
  }

  predicate isSanitizer(DataFlow::Node sanitizer) { literalSanitizer(sanitizer) }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // String concatenation propagation
    exists(StringConcatenationOperation s |
      s.getAnOperand() = node1.asExpr() and node2.asExpr() = s
    )
    or
    // String format propagation
    exists(MethodAccess fmt |
      fmt.getMethod().getName().matches("format") and
      fmt.getAnArgument() = node1.asExpr() and node2.asExpr() = fmt
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "A formatted or concatenated string was detected as input to a Runtime call. " +
  "This could result in command injection if variables are user-controlled."