/**
 * @name Tainted File Path
 * @description Detected user input controlling a file path. An attacker could control the location of this
 *              file, including directory traversal with '../'. Ensure user-controlled variables in file paths
 *              are sanitized. Consider using org.apache.commons.io.FilenameUtils.getName().
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/tainted-file-path
 * @tags security
 *       external/cwe/cwe-023
 *       external/owasp/a01
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.spring.SpringController
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.Type
import semmle.code.java.expr.Call

class TaintedFileConfig extends TaintTracking::Configuration {
  TaintedFileConfig() { this = "TaintedFileConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m, Parameter p, Annotation a, string annotationType |
      m.getAParameter() = p and
      p.getAnAnnotation() = a and
      a.getType().getName() = annotationType and
      (
        annotationType = "RequestBody" or
        annotationType = "PathVariable" or
        annotationType = "RequestParam" or
        annotationType = "RequestHeader" or
        annotationType = "CookieValue" or
        annotationType = "ModelAttribute"
      ) and
      not p.getType() instanceof PrimitiveType and
      not p.getType() instanceof BoxedType and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(ConstructorCall cc |
      (
        cc.getConstructor().getDeclaringType().hasQualifiedName("java.io", "File") or
        cc.getConstructor().getDeclaringType().hasQualifiedName("java.io", "FileReader") or
        cc.getConstructor().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") or
        cc.getConstructor().getDeclaringType().hasQualifiedName("java.io", "FileOutputStream")
      ) and
      sink.asExpr() = cc.getArgument(0)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().getName() = "get" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") and
      sink.asExpr() = ma.getArgument(0)
    )
    or
    exists(MethodAccess ma |
      (
        ma.getMethod().getName() = "getResourceAsStream" or
        ma.getMethod().getName() = "getResource"
      ) and
      sink.asExpr() = ma.getQualifier()
    )
    or
    exists(ConstructorCall cc |
      (
        cc.getConstructor().getDeclaringType().hasQualifiedName("org.springframework.core.io", "ClassPathResource") or
        cc.getConstructor().getDeclaringType().hasQualifiedName("javax.xml.transform", "StreamSource")
      ) and
      sink.asExpr() = cc.getArgument(0)
    )
    or
    exists(MethodAccess ma |
      (
        (ma.getMethod().getName() = "getFile" and
         ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.util", "ResourceUtils"))
        or
        (ma.getMethod().getName() = "openOutputStream" and
         ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils"))
      ) and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getName" and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      sanitizer.asExpr() = ma
    )
  }
}

from TaintedFileConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential path traversal vulnerability from $@.", source.getNode(),
  "User-provided value"