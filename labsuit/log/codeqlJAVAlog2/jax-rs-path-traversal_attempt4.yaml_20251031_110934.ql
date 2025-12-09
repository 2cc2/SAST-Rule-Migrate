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
    getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PathParam")
  }
}

class FileCreationSink extends DataFlow::Node {
  FileCreationSink() {
    exists(ConstructorCall call | 
      call.getConstructedType().hasQualifiedName("java.io", "File") and
      this.asExpr() = call.getArgument(0)
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::Node {
  FilenameUtilsSanitizer() {
    exists(MethodCall call |
      call.getMethod().hasQualifiedName("org.apache.commons.io", "FilenameUtils", "getName")
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