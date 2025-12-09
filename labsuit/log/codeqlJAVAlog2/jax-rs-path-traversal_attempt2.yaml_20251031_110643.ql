/**
 * @name JAX-RS Path Traversal Vulnerability
 * @description Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'.
 * @kind path-problem
 * @problem.severity warning
 * @id java/jax-rs-path-traversal
 * @tags security
 *   jax-rs
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow

class JaxRsPathParam extends DataFlow::Node {
  JaxRsPathParam() {
    exists(Parameter p |
      p.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PathParam") and
      this.asParameter() = p
    )
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
      call.getMethod().hasQualifiedName("org.apache.commons.io", "FilenameUtils", "getName") and
      this.asExpr() = call.getArgument(0)
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

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from JaxRsPathTraversalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), "Potential path traversal vulnerability from JAX-RS path parameter to file creation", source.getNode(),
  "User-provided value flows to file creation without proper sanitization"