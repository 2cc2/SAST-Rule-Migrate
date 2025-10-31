/**
 * @name Tainted file path
 * @description Detected user input controlling a file path. An attacker could control the location
 *              of this file, to include going backwards in the directory with '../'. To address this,
 *              ensure that user-controlled variables in file paths are sanitized. You may also consider
 *              using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only
 *              retrieve the file name from the path.
 * @id java/tainted-file-path
 * @kind path-problem
 * @severity error
 * @tags security
 *       java
 *       spring
 * @cwe CWE-23: Relative Path Traversal
 * @owasp A01:2021 - Broken Access Control
 */

import java
import DataFlow::PathGraph
import semmle.code.java.dataflow.TaintTracking

class SpringParameterAnnotation extends AnnotationType {
  SpringParameterAnnotation() {
    this.hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody") or
    this.hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") or
    this.hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") or
    this.hasQualifiedName("org.springframework.web.bind.annotation", "RequestHeader") or
    this.hasQualifiedName("org.springframework.web.bind.annotation", "CookieValue") or
    this.hasQualifiedName("org.springframework.web.bind.annotation", "ModelAttribute")
  }
}

class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    exists(Parameter p |
      p = this.asParameter() and
      not p.getType() instanceof BoxedType and
      not p.getType() instanceof PrimitiveType and
      exists(SpringParameterAnnotation a | a = p.getAnAnnotation())
    )
  }
}

class FileOperationSink extends DataFlow::Node {
  FileOperationSink() {
    exists(MethodAccess ma |
      ma = this.asExpr() and (
        ma.getMethod().hasName("<init>") and ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") or
        ma.getMethod().hasName("<init>") and ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileReader") or
        ma.getMethod().hasName("<init>") and ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") or
        ma.getMethod().hasName("get") and ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") or
        (ma.getMethod().hasName("getResource") or ma.getMethod().hasName("getResourceAsStream")) and 
          ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") or
        ma.getMethod().hasName("getFile") and ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.util", "ResourceUtils") or
        ma.getMethod().hasName("openOutputStream") and ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") or
        ma.getMethod().hasName("<init>") and ma.getMethod().getDeclaringType().hasQualifiedName("javax.xml.transform.stream", "StreamSource") or
        ma.getMethod().hasName("<init>") and ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.core.io", "ClassPathResource")
      )
    )
  }
}

class FilenameUtilsSanitizer extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getName") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      pred.asExpr() = ma.getArgument(0) and
      succ.asExpr() = ma
    )
  }
}

class TaintedFilePathConfiguration extends TaintTracking::Configuration {
  TaintedFilePathConfiguration() { this = "TaintedFilePathConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UserInputSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileOperationSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getName") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      sanitizer.asExpr() = ma
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedFilePathConfiguration config
where config.hasFlowPath(source, sink)
select sink, source, sink,
  "Detected user input controlling a file path. An attacker could control the location of this file."