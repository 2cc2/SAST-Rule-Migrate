/**
 * @name JAX-RS Path Traversal Vulnerability
 * @description Detects potential path traversal vulnerabilities in JAX-RS endpoints where
 *              user-controlled path parameters are used in file operations without proper sanitization.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id java/jax-rs-path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-2021-top25
 *       external/cwe/cwe-2022-top25
 *       owasp/a01
 *       owasp/a05
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.jaxrs.JaxRsRequestParameters

predicate isFileConstructor(Expr arg) {
  exists(Constructor c | 
    c.getDeclaringType().hasQualifiedName("java.io", "File") and
    arg = c.getAnArgument()
  )
}

from Method m, Parameter p, Expr sink
where
  // Source: JAX-RS PathParam annotated parameter
  JaxRsRequestParameters::isPathParam(p) and
  // Sink: File constructor argument
  isFileConstructor(sink) and
  // Data flow from source to sink
  exists(DataFlow::PathNode source, DataFlow::PathNode sinkNode |
    DataFlow::localFlow(source, sinkNode) and
    source.asParameter() = p and
    sinkNode.asExpr() = sink
  )
select sink, "Potential path traversal vulnerability via user-controlled path parameter $@.", p, 
  "This parameter is used in file operations without proper sanitization. Consider validating or sanitizing the input path."