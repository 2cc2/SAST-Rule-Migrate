/**
 * @name JAX-RS Path Traversal
 * @description Detected a potential path traversal. A malicious actor could control the location of this file,
 * to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables
 * in file paths are sanitized. You may also consider using a utility method such as 
 * org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 *       jax-rs
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.JAXRS

class PathParamSource extends DataFlow::Node {
  PathParamSource() { 
    exists(JAXRSPathConstraint c | c.getAnAnnotation() instanceof JAXRSPathParam |
      this.asParameter() = c.getAnAnnotation().getDeclaration()
    )
  }
}

class FileCreationSink extends DataFlow::Node {
  FileCreationSink() {
    exists(Constructor f | 
      f.getDeclaringType().hasQualifiedName("java.io", "File") and
      this.asExpr() = f.getAConstructorCall()
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::Node {
  FilenameUtilsSanitizer() {
    exists(Method m |
      m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      m.getName() = "getName" and
      this.asExpr() = m.getACall()
    )
  }
}

class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() { this = "PathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof PathParamSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileCreationSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from DataFlow::Node source, DataFlow::Node sink, PathTraversalConfig config
where config.hasFlow(source, sink)
select sink, "Potential path traversal from user-provided JAX-RS path parameter to file creation"