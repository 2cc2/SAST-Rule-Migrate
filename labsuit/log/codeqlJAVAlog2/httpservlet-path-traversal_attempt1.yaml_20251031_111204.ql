/**
 * @name Path Traversal Vulnerability
 * @kind problem
 * @id java/httpservlet-path-traversal
 * @severity error
 * @description Detected a potential path traversal. A malicious actor could control
 *              the location of this file, to include going backwards in the directory
 *              with '../'. To address this, ensure that user-controlled variables in
 *              file paths are sanitized. You may also consider using a utility method
 *              such as org.apache.commons.io.FilenameUtils.getName(...) to only
 *              retrieve the file name from the path.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.PathTraversal

class HttpServletRequestSource extends DataFlow::Node {
  HttpServletRequestSource() {
    exists(Method m, Parameter p |
      (
        m.getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
        p = m.getAParameter() and
        this.asParameter() = p
      )
    )
  }
}

class CookieGetValueSource extends DataFlow::Node {
  CookieGetValueSource() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
      ma.getMethod().getName() = "getValue" and
      this.asExpr() = ma
    )
  }
}

class ArrayLocalSource extends DataFlow::Node {
  ArrayLocalSource() {
    exists(LocalVariable lv |
      lv.getType() instanceof ArrayType and
      this.asVariable() = lv
    )
  }
}

class FileOperationsSink extends DataFlow::Node {
  FileOperationsSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileOutputStream") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileInputStream")
      ) and
      this.asExpr() = ma
    )
  }
}

class FilenameUtilsSanitizer extends TaintTracking::AdditionalSanitizer {
  FilenameUtilsSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      ma.getMethod().getName() = "getName" and
      this.asExpr() = ma
    )
  }
}

class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() { this = "PathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof HttpServletRequestSource or
    source instanceof CookieGetValueSource or
    source instanceof ArrayLocalSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileOperationsSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof FilenameUtilsSanitizer
  }

  override predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Propagation from request to cookie
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
      ma.getMethod().getName() = "getValue" and
      node1.asParameter() = ma.getAnArgument() and
      node2.asExpr() = ma
    )
    or
    // Propagation through arrays
    exists(ArrayAccess aa | node1.asVariable() = aa.getArray() and node2.asVariable() = aa)
  }
}

from PathTraversalConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential path traversal vulnerability from $@.", source, source.toString()