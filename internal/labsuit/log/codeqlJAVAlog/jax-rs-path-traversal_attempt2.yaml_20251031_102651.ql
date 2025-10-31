/**
 * @name JAX-RS Path Traversal Vulnerability
 * @description Detected a potential path traversal. A malicious actor could control the location of this file,
 *              to include going backwards in the directory with '../'. To address this, ensure that user-controlled 
 *              variables in file paths are sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/jax-rs-path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.JAXRS

class JAXRSPathParamSource extends DataFlow::Node {
  JAXRSPathParamSource() {
    exists(Method m, MethodParameter p |
      m.getAParameter() = p and
      p.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PathParam") and
      this.asParameter() = p
    )
  }
}

class FileCreationSink extends DataFlow::Node {
  FileCreationSink() {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "File") and
      this.asExpr() = cc
    )
  }

  override predicate hasValueUnderApproximation(Expr expr) {
    exists(FileCreationSink fcs | fcs.getANode() = expr)
  }
}

class FilenameUtilsSanitizer extends DataFlow::Node {
  FilenameUtilsSanitizer() {
    exists(MethodInvocation mi |
      mi.getMethod().hasQualifiedName("org.apache.commons.io", "FilenameUtils", "getName") and
      this.asExpr() = mi
    )
  }

  override predicate hasValueUnderApproximation(Expr expr) {
    exists(FilenameUtilsSanitizer fus | fus.getANode() = expr)
  }
}

class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() { this = "PathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof JAXRSPathParamSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileCreationSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, PathTraversalConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential path traversal vulnerability from user-provided value to file creation."