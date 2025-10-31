/**
 * @name Tainted file path
 * @description Detected user input controlling a file path. An attacker could control the location of this file, 
 * to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables 
 * in file paths are sanitized. You may also consider using a utility method such as 
 * org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.
 * @kind problem
 * @problem.severity error
 * @id java/tainted-file-path
 * @tags security
 *   java
 *   spring
 *   external/cwe/cwe-023
 *   external/owasp/a01:2021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class InputSource extends DataFlow::Node {
  InputSource() {
    exists(Method m, Parameter p |
      m.getAnAnnotation() instanceof SpringParameterAnnotation and
      p = m.getParameter(_) and
      not p.getType() instanceof BoxedPrimitiveType and
      not p.getType() instanceof PrimitiveType and
      this.asParameter() = p
    )
  }
}

private class SpringParameterAnnotation extends AnnotationType {
  SpringParameterAnnotation() {
    this.hasQualifiedName(["org", "springframework", "web", "bind", "annotation"], "RequestBody") or
    this.hasQualifiedName(["org", "springframework", "web", "bind", "annotation"], "PathVariable") or
    this.hasQualifiedName(["org", "springframework", "web", "bind", "annotation"], "RequestParam") or
    this.hasQualifiedName(["org", "springframework", "web", "bind", "annotation"], "RequestHeader") or
    this.hasQualifiedName(["org", "springframework", "web", "bind", "annotation"], "CookieValue") or
    this.hasQualifiedName(["org", "springframework", "web", "bind", "annotation"], "ModelAttribute")
  }
}

class FileOperationSink extends DataFlow::Node {
  FileOperationSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") and 
       ma.getMethod().getName() = "<init>") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileReader") and 
       ma.getMethod().getName() = "<init>") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and 
       ma.getMethod().getName() = "<init>") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") and 
       ma.getMethod().getName() = "get") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") and 
       (ma.getMethod().getName() = "getResource" or 
        ma.getMethod().getName() = "getResourceAsStream")) or
      (ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.util", "ResourceUtils") and 
       ma.getMethod().getName() = "getFile") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and 
       ma.getMethod().getName() = "openOutputStream") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("javax.xml.transform.stream", "StreamSource") and 
       ma.getMethod().getName() = "<init>") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.core.io", "ClassPathResource") and 
       ma.getMethod().getName() = "<init>") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class FilenameUtilsSanitizer extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      ma.getMethod().getName() = "getName" and
      succ.asExpr() = ma and
      pred.asExpr() = ma.getArgument(0)
    )
  }
}

class TaintedFilePathConfig extends TaintTracking::Configuration {
  TaintedFilePathConfig() { this = "TaintedFilePathConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof InputSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof FileOperationSink }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      ma.getMethod().getName() = "getName" and
      node.asExpr() = ma
    )
  }
}

from TaintedFilePathConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Detected user input controlling a file path ($@).", source, source.toString()