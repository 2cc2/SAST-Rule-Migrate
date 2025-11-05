/**
 * @name Tainted file path
 * @description Detected user input controlling a file path. An attacker could control the location 
 * of this file, to include going backwards in the directory with '../'. To address this, 
 * ensure that user-controlled variables in file paths are sanitized. Consider using 
 * org.apache.commons.io.FilenameUtils.getName() to only retrieve the file name from the path.
 * @kind problem
 * @problem.severity error
 * @id java/tainted-file-path
 * @tags security
 *       java
 *       spring
 *       external/cwe/cwe-023
 *       external/owasp/a01:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.spring.SpringController

class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    exists(Method m, Parameter p | 
      p = m.getAParameter() and
      p.getType() instanceof PrimitiveType and
      not p.getType().toString().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)") and
      (
        exists(Annotation a | 
          a = p.getAnAnnotation() and
          a.getType().getName().matches("(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)")
        )
      )
    )
  }
}

class FileOperationSink extends DataFlow::Node {
  FileOperationSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") and
        ma.getMethod().hasName("<init>")
      ) or
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileReader") and
        ma.getMethod().hasName("<init>")
      ) or
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and
        ma.getMethod().hasName("<init>")
      ) or
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") and
        ma.getMethod().hasName("get")
      ) or
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") and
        ma.getMethod().hasName("getResource")
      ) or
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") and
        ma.getMethod().hasName("getResourceAsStream")
      ) or
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.util", "ResourceUtils") and
        ma.getMethod().hasName("getFile")
      ) or
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
        ma.getMethod().hasName("openOutputStream")
      ) or
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.xml.transform.stream", "StreamSource") and
        ma.getMethod().hasName("<init>")
      ) or
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.core.io", "ClassPathResource") and
        ma.getMethod().hasName("<init>")
      )
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::Node {
  FilenameUtilsSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      ma.getMethod().hasName("getName")
    )
  }
}

class TaintedFilepathConfig extends TaintTracking::Configuration {
  TaintedFilepathConfig() { this = "TaintedFilepathConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof UserInputSource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileOperationSink
  }
  
  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from DataFlow::Node source, DataFlow::Node sink, TaintedFilepathConfig config
where config.hasFlow(source, sink)
select sink, "Potential path traversal vulnerability from user input to file operation"