/**
 * @name JAX-RS Path Traversal
 * @description Detected a potential path traversal. A malicious actor could control the location of this file,
 *              to include going backwards in the directory with '../'. To address this, ensure that user-controlled
 *              variables in file paths are sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @id java/jax-rs-path-traversal
 * @tags security
 *       external/cwe/cwe-22
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class JaxRsPathParam extends DataFlow::Parameter {
  JaxRsPathParam() {
    exists(Annotation annot |
      annot.getType().hasQualifiedName("javax.ws.rs", "PathParam") and
      this.getAnAnnotation() = annot
    )
  }
}

class FileCreationSink extends DataFlow::Node {
  FileCreationSink() {
    exists(Constructor ctor |
      ctor.getDeclaringType().hasQualifiedName("java.io", "File") and
      this.asExpr() = ctor.getAnArgument()
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::Node {
  FilenameUtilsSanitizer() {
    exists(Method method |
      method.hasQualifiedName("org.apache.commons.io", "FilenameUtils", "getName") and
      this.asExpr().(MethodAccess).getMethod() = method
    )
  }
}

class JaxRsPathTraversalConfig extends TaintTracking::Configuration {
  JaxRsPathTraversalConfig() { this = "JaxRsPathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof JaxRsPathParam
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileCreationSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof FilenameUtilsSanitizer
  }
}

from JaxRsPathTraversalConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Potential path traversal from JAX-RS path parameter (" + source.getNode() + ") to file creation"