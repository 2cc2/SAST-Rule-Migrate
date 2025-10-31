/**
 * @id tainted-file-path
 * @severity ERROR
 * @message Detected user input controlling a file path. An attacker could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.
 * @kind path-problem
 * @tags security
 *   java
 *   spring
 * @cwe CWE-23: Relative Path Traversal
 * @owasp A01:2021 - Broken Access Control
 */

import java
import codeql.java.dataflow.DataFlow
import codeql.java.dataflow.TaintTracking
import codeql.java.frameworks.spring.SpringController

class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    exists(Method method, Parameter p |
      p = method.getAParameter() and
      (this.asParameter() = p)
    ) and
    not exists(PrimitiveType t | t = this.getType()) and
    not exists(BoxedType t | t = this.getType()) and
    exists(Annotation a |
      a.getType().getName().matches("RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute") and
      a = this.getAnAnnotation()
    )
  }
}

class FileOperationSink extends DataFlow::Node {
  FileOperationSink() {
    exists(MethodAccess ma |
      (ma.getMethod().hasName("<init>") and ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File")) or
      (ma.getMethod().hasName("<init>") and ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileReader")) or
      (ma.getMethod().hasName("<init>") and ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileInputStream")) or
      (ma.getMethod().hasName("get") and ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths")) or
      (ma.getMethod().hasName("getResource") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class")) or
      (ma.getMethod().hasName("getResourceAsStream") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class")) or
      (ma.getMethod().hasName("getFile") and ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.util", "ResourceUtils")) or
      (ma.getMethod().hasName("openOutputStream") and ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils")) or
      (ma.getMethod().hasName("<init>") and ma.getMethod().getDeclaringType().hasQualifiedName("javax.xml.transform.stream", "StreamSource")) or
      (ma.getMethod().hasName("<init>") and ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.core.io", "ClassPathResource")) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class FilenameUtilsSanitizer extends TaintTracking::Sanitizer {
  override predicate isSanitizer(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getName") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      node.asExpr() = ma.getArgument(0)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  TaintTracking::localTaint(source, sink) and
  source.getNode() instanceof UserInputSource and
  sink.getNode() instanceof FileOperationSink
select sink, "Potentially unsafe file operation using user-controlled input", source, "User input comes from here"