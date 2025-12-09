import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import DataFlow::PathGraph

class JaxRsPathParam extends DataFlow::Parameter {
  JaxRsPathParam() {
    exists(Annotation a | 
      a = this.getAnAnnotation() and
      a.getType().hasQualifiedName("javax.ws.rs", "PathParam")
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

from JaxRsPathTraversalConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential path traversal from JAX-RS path parameter to file creation"