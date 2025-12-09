/**
 * @name Tainted file path
 * @description Detected user input controlling a file path. An attacker could control the location of this file,
 *              to include going backwards in the directory with '../'. To address this, ensure that user-controlled
 *              variables in file paths are sanitized.
 * @kind path-problem
 * @problem.severity error
 * @id java/tainted-file-path
 * @tags security
 *       external/cwe/cwe-023
 *       external/owasp/a01
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.Annotation
import semmle.code.java.Type

class SpringParameterAnnotation extends Annotation {
  SpringParameterAnnotation() {
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody") or
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") or
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") or
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestHeader") or
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "CookieValue") or
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "ModelAttribute")
  }
}

class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    exists(Parameter p |
      this.asParameter() = p and
      not p.getType() instanceof BoxedType and
      not p.getType() instanceof PrimitiveType and
      exists(SpringParameterAnnotation a | a = p.getAnAnnotation())
    )
  }
}

class FileOperationSink extends DataFlow::Node {
  FileOperationSink() {
    exists(MethodAccess ma |
      this.asExpr() = ma and
      (
        ma.getMethod().getName() = "<init>" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File")
        or
        ma.getMethod().getName() = "<init>" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileReader")
        or
        ma.getMethod().getName() = "<init>" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileInputStream")
        or
        ma.getMethod().getName() = "get" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths")
        or
        (ma.getMethod().getName() = "getResource" or ma.getMethod().getName() = "getResourceAsStream") and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class")
        or
        ma.getMethod().getName() = "getFile" and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.util", "ResourceUtils")
        or
        ma.getMethod().getName() = "openOutputStream" and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils")
        or
        ma.getMethod().getName() = "<init>" and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.xml.transform.stream", "StreamSource")
        or
        ma.getMethod().getName() = "<init>" and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.core.io", "ClassPathResource")
      )
    )
  }
}

class FilenameUtilsSanitizer extends TaintTracking::Sanitizer {
  FilenameUtilsSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getName" and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils")
    )
  }
}

from UserInputSource source, FileOperationSink sink
where TaintTracking::localTaint(DataFlow::parameterNode(source), DataFlow::exprNode(sink))
select sink, "Detected user input controlling a file path. An attacker could control the location of this file."