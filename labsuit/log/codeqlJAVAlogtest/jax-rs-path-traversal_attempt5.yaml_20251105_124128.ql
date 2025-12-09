/**
 * @name Potential Path Traversal in JAX-RS
 * @description Detected a potential path traversal. A malicious actor could control the location of this file,
 * to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables
 * in file paths are sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id java/jax-rs-path-traversal
 * @tags security
 *       jax-rs
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking2

class IsPathParameter extends Parameter {
  IsPathParameter() {
    exists(Annotation a |
      a = this.getAnAnnotation() and
      (
        a.getType().hasQualifiedName("javax.ws.rs", "PathParam") or
        a.toString().matches("@PathParam")
      )
    )
  }
}

class FileConstructorCall extends Call {
  FileConstructorCall() {
    getCallee().hasName("<init>") and
    getCallee().getDeclaringType().hasQualifiedName("java.io", "File")
  }
}

class FilenameUtilsSanitizer extends Call {
  FilenameUtilsSanitizer() {
    getCallee().hasName("getName") and
    getCallee().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils")
  }
}

class PathTraversalConfig extends TaintTracking2::Configuration {
  PathTraversalConfig() { this = "JaxRsPathTraversal" }

  override predicate isSource(DataFlow::Node source) {
    exists(IsPathParameter param |
      source.asParameter() = param
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(FileConstructorCall call |
      sink.asExpr() = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(FilenameUtilsSanitizer sanitizer |
      node.asExpr() = sanitizer
    )
  }
}

from PathTraversalConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential path traversal from $@ to unsanitized file creation", source,
  source.toString() + " to " + sink.toString()