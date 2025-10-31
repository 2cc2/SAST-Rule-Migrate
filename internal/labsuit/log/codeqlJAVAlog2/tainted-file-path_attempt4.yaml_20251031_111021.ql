/**
 * @id tainted-file-path
 * @kind problem
 * @name Tainted file path
 * @description Detected user input controlling a file path. An attacker could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.
 * @severity error
 * @tags security
 *       java
 *       spring
 * @precision high
 */

import java
import DataFlow
import TaintTracking
import semmle.code.java.Param
import semmle.code.java.Annotation
import semmle.code.java.MethodAccess

predicate isUserInputParameter(Parameter p) {
  not p.getType().toString().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)")
  and
  exists(p.getAnAnnotation() | annotationTypeName = getType().getName() |
    annotationTypeName.matches("RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute")
  )
}

class FileOperationSink extends DataFlow::Node {
  FileOperationSink() {
    exists(MethodAccess ma | 
      ma = this.getNode().asExpr() |
      (
        (ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") and ma.getMethod().getName() = "<init>")
        or
        (ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileReader") and ma.getMethod().getName() = "<init>")
        or
        (ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and ma.getMethod().getName() = "<init>")
        or
        (ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") and ma.getMethod().getName() = "get")
        or
        (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") and ma.getMethod().getName() = "getResource")
        or
        (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") and ma.getMethod().getName() = "getResourceAsStream")
        or
        (ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.util", "ResourceUtils") and ma.getMethod().getName() = "getFile")
        or
        (ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and ma.getMethod().getName() = "openOutputStream")
        or
        (ma.getMethod().getDeclaringType().hasQualifiedName("javax.xml.transform.stream", "StreamSource") and ma.getMethod().getName() = "<init>")
        or
        (ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.core.io", "ClassPathResource") and ma.getMethod().getName() = "<init>")
      )
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::Node {
  FilenameUtilsSanitizer() {
    exists(MethodAccess ma |
      ma = this.getNode().asExpr() |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      ma.getMethod().getName() = "getName"
    )
  }
}

class TaintedPathConfiguration extends TaintTracking::Configuration {
  TaintedPathConfiguration() { this = "TaintedPathConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source.asParameter().isUserInputParameter()
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof FileOperationSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from DataFlow::Node source, DataFlow::Node sink
where any(TaintedPathConfiguration config).hasFlow(source, sink)
select sink, "Potential path traversal vulnerability due to unvalidated user input"