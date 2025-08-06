/**
 * @name Dangerous Class Deserialization in RMI
 * @description Using a non-primitive class with Java RMI may be an insecure deserialization vulnerability.
 *              This object could be manipulated by a malicious actor allowing them to execute code on your system.
 * @kind path-problem
 * @problem.severity warning
 * @id java/server-dangerous-class-deserialization
 * @tags security
 *       external/cwe/cwe-502
 *       external/owasp/a08
 *       externally-hardened
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class RMIMethod extends Method {
  RMIMethod() {
    this.getDeclaringType().getASupertype*().hasQualifiedName("java.rmi", "Remote") and
    this.getNumberOfParameters() > 0 and
    not this.getParameter(0).getType() instanceof PrimitiveType
  }
}

class RMIMethodCall extends Call {
  RMIMethodCall() {
    exists(RMIMethod m | this.getCallee() = m)
  }
}

class DangerousDeserializationConfig extends TaintTracking::Configuration {
  DangerousDeserializationConfig() { this = "DangerousDeserializationConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(RMIMethodCall call |
      source.asExpr() = call.getArgument(0)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(RefType t | 
      sink.getType() = t and 
      t.getASupertype*().hasQualifiedName("java.io", "Serializable")
    )
  }
}

from DangerousDeserializationConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Using a non-primitive class with Java RMI may be an insecure deserialization vulnerability. " +
  "Consider using an integer ID to look up your object, or alternative serialization schemes such as JSON."