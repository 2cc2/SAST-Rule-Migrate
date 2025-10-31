/**
 * @name JAX-RS Path Traversal
 * @description Detected a potential path traversal. A malicious actor could control
 *              the location of this file, to include going backwards in the directory
 *              with '../'. Ensure user-controlled variables in file paths are sanitized.
 * @kind problem
 * @id java/jax-rs-path-traversal
 * @tags security
 *       jax-rs
 * @severity Warning
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.JAXRS

class PathParamSource extends TaintTracking::Source {
  PathParamSource() {
    exists(MethodParameter p |
      p.getAnnotatedDeclaration().getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PathParam") and
      this.asParameter() = p
    )
  }
}

class FileCreationSink extends TaintTracking::Sink {
  FileCreationSink() {
    exists(ConstructorCall call |
      call.getConstructedType().hasQualifiedName("java.io", "File") and
      this.asExpr() = call.getArgument(0)
    )
  }
}

class FilenameUtilsSanitizer extends TaintTracking::Sanitizer {
  FilenameUtilsSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("org.apache.commons.io", "FilenameUtils", "getName") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() { this = "PathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof PathParamSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof FileCreationSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from PathTraversalConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential path traversal vulnerability from JAX-RS path parameter to file creation."