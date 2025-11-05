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
import semmle.code.java.StringOperations
import DataFlow::PathGraph

class UserControlledInput extends DataFlow::Node {
  UserControlledInput() {
    exists(Parameter p | 
      this.asParameter() = p and
      not p.getAnAssignedValue() instanceof Literal
    )
    or
    exists(LocalVariableDecl l |
      this.asDefiningArgument() = l and
      not l.getInitializer() instanceof Literal
    )
  }
}

class RuntimeExecSink extends DataFlow::Node {
  RuntimeExecSink() {
    exists(Method m |
      m.hasName("exec") and
      m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      this.asExpr() = m.getACall().getArgument(0) or
      this.asExpr() = m.getACall().getArgument(1) or
      this.asExpr() = m.getACall().getArgument(2)
    )
  }
}

class RuntimeLoadLibrarySink extends DataFlow::Node {
  RuntimeLoadLibrarySink() {
    exists(Method m |
      m.hasName("loadLibrary") and
      m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      this.asExpr() = m.getACall().getArgument(0)
    )
  }
}

predicate literalSanitizer(DataFlow::Node node) {
  node.asExpr() instanceof Literal
}

module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof UserControlledInput }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof RuntimeExecSink or
    sink instanceof RuntimeLoadLibrarySink
  }

  predicate isSanitizer(DataFlow::Node sanitizer) { literalSanitizer(sanitizer) }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(StringConcatenationOperation s |
      s.getAnOperand() = node1.asExpr() and
      node2.asExpr() = s
    )
    or
    exists(MethodAccess fmt |
      fmt.getMethod().getName().matches("format") and
      fmt.getAnArgument() = node1.asExpr() and
      node2.asExpr() = fmt
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "A formatted or concatenated string was detected as input to a Runtime call. " +
  "This could result in command injection if variables are user-controlled."