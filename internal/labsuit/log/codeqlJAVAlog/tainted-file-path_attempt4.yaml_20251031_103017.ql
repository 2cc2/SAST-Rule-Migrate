/**
 * @name Tainted file path
 * @description Detected user input controlling a file path. An attacker could control
 *              the location of this file, to include going backwards in the directory
 *              with '../'. To address this, ensure that user-controlled variables in
 *              file paths are sanitized.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/tainted-file-path
 * @tags security
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/owasp/a01:2021
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.spring.SpringController

class UserInputSource extends DataFlow::ExprNode {
  UserInputSource() {
    exists(Method m, Parameter p |
      m instanceof SpringControllerMethod and
      p = m.getAParameter() and
      this.asExpr() = p.getAnAccess() and
      not p.getType().(BoxedType).getUnderlyingType() instanceof PrimitiveType and
      not p.getType() instanceof PrimitiveType and
      exists(Annotation a | a = p.getAnAnnotation() |
        a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") or
        a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") or
        a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestHeader") or
        a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "CookieValue") or
        a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "ModelAttribute") or
        a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody")
      )
    )
  }
}

class FileOperationSink extends DataFlow::Node {
  FileOperationSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["<init>", "get", "getResource", "getResourceAsStream", "getFile", "openOutputStream"]) and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileReader") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.util", "ResourceUtils") or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") or
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.xml.transform.stream", "StreamSource") or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.core.io", "ClassPathResource")
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class FilenameUtilsSanitizer extends TaintTracking::Sanitizer {
  FilenameUtilsSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getName") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      this.getASanitizedNode() = ma
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where TaintTracking::localTaint(
  DataFlow::parameterNode(source), DataFlow::exprNode(sink),
  "Tainted file path flow", FilenameUtilsSanitizer()
)
select sink.getNode(), source, sink, "Potentially tainted file path from user input"