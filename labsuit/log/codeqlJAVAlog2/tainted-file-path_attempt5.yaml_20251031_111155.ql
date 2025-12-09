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

import python
import semmle.python.dataflow.DataFlow
import semmle.python.dataflow.TaintTracking
import semmle.python.Concepts

predicate isUserInputParameter(Parameter p) {
  not p.getType().toString().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)$")
  and
  exists(Annotation annotation | annotation = p.getAnAnnotation() |
    annotation.getType().getName().matches("RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute")
  )
}

class FileOperationSink extends DataFlow::Node {
  FileOperationSink() {
    exists(Call call | 
      call = this.asExpr() and
      (
        (call.getCalleeName() = "File" and call.getImportedFrom() = "java.io")
        or
        (call.getCalleeName() = "FileReader" and call.getImportedFrom() = "java.io")
        or
        (call.getCalleeName() = "FileInputStream" and call.getImportedFrom() = "java.io")
        or
        (call.getCalleeName() = "get" and call.getImportedFrom() = "java.nio.file.Paths")
        or
        (call.getCalleeName() = "getResource" and call.getImportedFrom() = "java.lang.Class")
        or
        (call.getCalleeName() = "getResourceAsStream" and call.getImportedFrom() = "java.lang.Class")
        or
        (call.getCalleeName() = "getFile" and call.getImportedFrom() = "org.springframework.util.ResourceUtils")
        or
        (call.getCalleeName() = "openOutputStream" and call.getImportedFrom() = "org.apache.commons.io.FileUtils")
        or
        (call.getCalleeName() = "StreamSource" and call.getImportedFrom() = "javax.xml.transform.stream")
        or
        (call.getCalleeName() = "ClassPathResource" and call.getImportedFrom() = "org.springframework.core.io")
      )
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::Node {
  FilenameUtilsSanitizer() {
    exists(Call call |
      call = this.asExpr() and
      call.getCalleeName() = "getName" and
      call.getImportedFrom() = "org.apache.commons.io.FilenameUtils"
    )
  }
}

class TaintedPathConfiguration extends TaintTracking::Configuration {
  TaintedPathConfiguration() { this = "TaintedPathConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p | p = source.asParameter() and isUserInputParameter(p))
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof FileOperationSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from DataFlow::Node source, DataFlow::Node sink, TaintedPathConfiguration config
where config.hasFlow(source, sink)
select sink, "Potential path traversal vulnerability due to unvalidated user input"