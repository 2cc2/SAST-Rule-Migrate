/**
 * @name JAX-RS Path Traversal
 * @description Detects potential path traversal vulnerabilities in JAX-RS applications where
 *              user-controlled path parameters are directly used in file operations.
 * @kind path-problem
 * @problem.severity warning
 * @id java/jax-rs-path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-2021-top25
 *       external/cwe/cwe-2022-top25
 *       owasp-a05:2017
 *       owasp-a01:2021
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.frameworks.jaxrs.JaxRS

class JaxRsPathParameterToFileSink extends DataFlow::Configuration {
  JaxRsPathParameterToFileSink() { this = "JaxRsPathParameterToFileSink" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodParameter mp |
      mp.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PathParam") and
      source.asParameter() = mp
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "File") and
      sink.asExpr() = cc.getAnArgument()
    )
  }
}

from JaxRsPathParameterToFileSink config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential path traversal vulnerability. User-controlled path parameter is used in file operation without proper sanitization."