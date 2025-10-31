/**
 * @name JAX-RS Path Traversal
 * @description Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.
 * @kind path-problem
 * @id java/jax-rs-path-traversal
 * @security-severity 8.0
 * @tags security
 *       jax-rs
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.JAXRS

class PathParamSource extends DataFlow::Source {
  PathParamSource() {
    exists(MethodParameter p |
      p.hasName("PathParam") or p.hasName("@javax.ws.rs.PathParam")
    )
  }
}

class FileCreationSink extends DataFlow::Sink {
  FileCreationSink() {
    exists(Constructor c |
      c.getDeclaringType().hasQualifiedName("java.io", "File") and
      c.getAnArgument().toString().matches("%VAR%")
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::Sanitizer {
  FilenameUtilsSanitizer() {
    exists(Method m |
      m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      m.hasName("getName")
    )
  }
}

class JaxRsPathTraversalConfig extends TaintTracking::Configuration {
  JaxRsPathTraversalConfig() { this = "JaxRsPathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof PathParamSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof FileCreationSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from JaxRsPathTraversalConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential path traversal vulnerability from $@ to $@.",
  source, "user input",
  sink, "file creation"