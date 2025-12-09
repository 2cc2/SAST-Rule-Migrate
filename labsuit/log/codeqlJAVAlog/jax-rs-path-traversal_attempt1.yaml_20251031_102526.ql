/**
 * @name JAX-RS Path Traversal
 * @description Detected a potential path traversal. A malicious actor could control the location of this file, 
 * to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables 
 * in file paths are sanitized. You may also consider using a utility method such as 
 * org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.
 * @severity Warning
 * @id jax-rs-path-traversal
 * @tags security
 * @tags jax-rs
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.JAXRS

class JAXRSPathParamSource extends DataFlow::Node {
  JAXRSPathParamSource() {
    exists(Method m, MethodParameter mp |
      mp = m.getAParameter() and
      mp.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PathParam") and
      this.asParameter() = mp
    )
  }
}

class FileCreationSink extends DataFlow::Node {
  FileCreationSink() {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "File") and
      this.asExpr() = cc.getArgument(0)
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::Node {
  FilenameUtilsSanitizer() {
    exists(MethodInvocation mi |
      mi.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      mi.getMethod().getName() = "getName" and
      this.asExpr() = mi
    )
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

from PathTraversalConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential path traversal vulnerability from JAX-RS path parameter to file creation"