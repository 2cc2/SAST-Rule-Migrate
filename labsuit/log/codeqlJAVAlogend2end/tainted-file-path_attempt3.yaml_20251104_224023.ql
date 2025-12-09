/**
 * @name Tainted file path
 * @description Detected user input controlling a file path. An attacker could control the location of this
 *    file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled
 *    variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...)
 *    to only retrieve the file name from the path.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/tainted-file-path
 * @tags security
 *       external/cwe/cwe-023
 *       owasp-a1
 */

import codeql.java.DataFlow
import codeql.java.TaintTracking
import codeql.java.Spring
import codeql.java.Type
import codeql.java.Entities
import codeql.java.Methods

class TaintedFileConfig extends TaintTracking::Configuration {
  TaintedFileConfig() { this = "TaintedFileConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m, Parameter p |
      m instanceof SpringRequestHandler and
      m.getAParameter() = p and
      not p.getType() instanceof PrimitiveType and
      not p.getType() instanceof BoxedType and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(ConstructorCall c |
      c.getConstructedType().hasQualifiedName("java.io", "File") and
      sink.asExpr() = c.getArgument(0)
    )
    or
    exists(ConstructorCall c |
      c.getConstructedType().hasQualifiedName("java.io", "FileReader") and
      sink.asExpr() = c.getArgument(0)
    )
    or
    exists(ConstructorCall c |
      c.getConstructedType().hasQualifiedName("java.io", "FileInputStream") and
      sink.asExpr() = c.getArgument(0)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("java.nio.file", "Paths", "get") and
      sink.asExpr() = ma.getArgument(0)
    )
    or
    exists(MethodAccess ma |
      (ma.getMethod().hasQualifiedName("java.lang", "Class", "getResource") or
       ma.getMethod().hasQualifiedName("java.lang", "Class", "getResourceAsStream")) and
      sink.asExpr() = ma.getArgument(0)
    )
    or
    exists(MethodAccess ma |
      (ma.getMethod().hasQualifiedName("org.springframework.util", "ResourceUtils", "getFile") or
       ma.getMethod().hasQualifiedName("org.apache.commons.io", "FileUtils", "openOutputStream")) and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("org.apache.commons.io", "FilenameUtils", "getName") and
      sanitizer.asExpr() = ma
    )
  }
}

from DataFlow::Node source, DataFlow::Node sink, TaintedFileConfig config
where config.hasFlow(source, sink)
select sink, "Potential path traversal vulnerability from user-controllable source $@.", source,
  "User input flows into file path operation"