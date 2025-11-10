/**
 * @name JAX-RS Path Traversal Vulnerability
 * @description Detects potential path traversal vulnerabilities in JAX-RS endpoints where PathParam values
 *              are directly used in File constructor without sanitization.
 * @kind path-problem
 * @problem.severity warning
 * @id java/jax-rs-path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-23
 *       owasp-a05:2017
 *       owasp-a01:2021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class JaxRsPathTraversalConfig extends TaintTracking::Configuration {
  JaxRsPathTraversalConfig() { 
    this = "JaxRsPathTraversalConfig" 
  }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m, Parameter p |
      (m.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PathParam") or
      m.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PathParam")) and
      p = m.getAParameter() and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "File") and
      sink.asExpr() = cc.getAnArgument()
    )
  }
}

from JaxRsPathTraversalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential path traversal vulnerability. User-controlled parameter is used in File constructor without sanitization."