/**
 * @name Tainted file path
 * @description Detected user input controlling a file path. An attacker could control the location
 *              of this file, to include going backwards in the directory with '../'.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id java/tainted-file-path
 * @tags security
 *       external/cwe/cwe-23
 *       external/owasp/a01b
 */
import java
import DataFlow::PathGraph
import DataFlow::MethodAccess

class SpringParameter extends DataFlow::Node {
  SpringParameter() {
    exists(string annotationName |
      annotationName = ["RequestBody", "PathVariable", "RequestParam", 
                       "RequestHeader", "CookieValue", "ModelAttribute"].getAnAnnotation() |
      this.getParameter().getAnAnnotation().toString().matches(annotationName)
    ) and
    not this.getParameter().getType().toString().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)")
  }
}

class FileOperationSink extends DataFlow::Node {
  FileOperationSink() {
    exists(DataFlow::MethodAccess ma |
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") and
        ma.getMethod().getName() = "<init>") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileReader") and
        ma.getMethod().getName() = "<init>") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and
        ma.getMethod().getName() = "<init>") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") and
        ma.getMethod().getName() = "get") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") and
        ma.getMethod().getName() = "getResource") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") and
        ma.getMethod().getName() = "getResourceAsStream") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.util", "ResourceUtils") and
        ma.getMethod().getName() = "getFile") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
        ma.getMethod().getName() = "openOutputStream") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("javax.xml.transform.stream", "StreamSource") and
        ma.getMethod().getName() = "<init>") or
      (ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.core.io", "ClassPathResource") and
        ma.getMethod().getName() = "<init>") |
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::Node {
  FilenameUtilsSanitizer() {
    exists(DataFlow::MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      ma.getMethod().getName() = "getName" |
      this.asExpr() = ma
    )
  }
}

class TaintedFilePathConfig extends TaintTracking::Configuration {
  TaintedFilePathConfig() { this = "TaintedFilePathConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SpringParameter
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileOperationSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedFilePathConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), "Detected user input controlling a file path. " +
  "An attacker could control the location of this file, to include going backwards in the directory with '../'. " +
  "To address this, ensure that user-controlled variables in file paths are sanitized. " +
  "You may also consider using a utility method such as " +
  "org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path."