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

predicate isFileConstructor(ConstructorCall call) {
  call.getConstructedType().hasQualifiedName("java.io", "File")
}

from DataFlow::PathNode source, DataFlow::PathNode sink, Method m, Parameter p, Expr arg
where
  p = source.asParameter() and
  JaxRsRequestParameters::isPathParam(p.getAnAccess()) and
  isFileConstructor(sink.asExpr()) and
  arg = sink.asExpr().getArgument(0) and
  DataFlow::flowPath(source, arg)
select sink, "Potential path traversal vulnerability via user-controlled path parameter $@.", 
  source.getNode(), "This parameter is used in file operations without proper sanitization."