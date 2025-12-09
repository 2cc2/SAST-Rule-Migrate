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
import DataFlow::PathGraph
import DataFlow
import JaxRs

predicate isFileConstructor(ConstructorCall c, DataFlow::Node arg) {
  c.getDeclaringType().hasQualifiedName("java.io", "File") and
  arg.asExpr() = c.getArgument(0)
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  exists(JaxRs::PathParamAnnotation param |
    param.getParameter() = source.asParameter()
  ) and
  exists(ConstructorCall c |
    isFileConstructor(c, sink)
  ) and
  DataFlow::flowPath(source, sink)
select sink, "Potential path traversal vulnerability via user-controlled path parameter $@.", 
  source.asParameter(), "This parameter is used in file operations without proper sanitization."