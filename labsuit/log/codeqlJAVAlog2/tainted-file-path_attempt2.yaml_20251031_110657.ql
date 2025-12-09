/**
 * @name Tainted File Path
 * @kind problem
 * @id java/tainted-file-path
 * @severity ERROR
 * @description Detected user input controlling a file path. An attacker could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.
 */

import java
import DataFlow
import TaintTracking

class UserInputSource extends DataFlow::ExprNode {
  UserInputSource() {
    exists(Parameter p |
      p = this.asParameter() and
      not p.getType().toString().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)") and
      exists(AnnotationElement a |
        a = p.getAnAnnotation() and
        a.getType().toString().matches("RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute")
      )
    )
  }
}

class FileOperationSink extends DataFlow::ExprNode {
  FileOperationSink() {
    exists(Expr ma |
      ma = this.asExpr() and
      ma instanceof MethodAccess and
      (
        ma.(MethodAccess).getMethod().getDeclaringType().hasQualifiedName("java.io", "File") and
        ma.(MethodAccess).getMethod().getName() = "<init>"
        or
        ma.(MethodAccess).getMethod().getDeclaringType().hasQualifiedName("java.io", "FileReader") and
        ma.(MethodAccess).getMethod().getName() = "<init>"
        or
        ma.(MethodAccess).getMethod().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and
        ma.(MethodAccess).getMethod().getName() = "<init>"
        or
        ma.(MethodAccess).getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") and
        ma.(MethodAccess).getMethod().getName() = "get"
        or
        ma.(MethodAccess).getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") and
        (ma.(MethodAccess).getMethod().getName() = "getResource" or ma.(MethodAccess).getMethod().getName() = "getResourceAsStream")
        or
        ma.(MethodAccess).getMethod().getDeclaringType().hasQualifiedName("org.springframework.util", "ResourceUtils") and
        ma.(MethodAccess).getMethod().getName() = "getFile"
        or
        ma.(MethodAccess).getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
        ma.(MethodAccess).getMethod().getName() = "openOutputStream"
        or
        ma.(MethodAccess).getMethod().getDeclaringType().hasQualifiedName("javax.xml.transform.stream", "StreamSource") and
        ma.(MethodAccess).getMethod().getName() = "<init>"
        or
        ma.(MethodAccess).getMethod().getDeclaringType().hasQualifiedName("org.springframework.core.io", "ClassPathResource") and
        ma.(MethodAccess).getMethod().getName() = "<init>"
      )
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::ExprNode {
  FilenameUtilsSanitizer() {
    exists(Expr ma |
      ma = this.asExpr() and
      ma instanceof MethodAccess and
      ma.(MethodAccess).getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      ma.(MethodAccess).getMethod().getName() = "getName"
    )
  }
}

class TaintedFilePathConfig extends TaintTracking::Configuration {
  TaintedFilePathConfig() { this = "TaintedFilePathConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof UserInputSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof FileOperationSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from TaintedFilePathConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "潜在的文件路径注入漏洞来自用户输入 $@", source, "用户输入"