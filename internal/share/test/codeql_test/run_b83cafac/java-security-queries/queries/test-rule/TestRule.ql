/**
 * @name Servlet Path Traversal
 * @description Detects potential path traversal vulnerabilities in Java servlets where user-controlled
 *              input flows into file operations without proper sanitization.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision medium
 * @id java/servlet-path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-073
 *       owasp-a05:2017
 *       owasp-a01:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.frameworks.Servlets

class ServletPathTraversalConfiguration extends TaintTracking::Configuration {
  ServletPathTraversalConfiguration() { this = "ServletPathTraversalConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      (
        ma.getMethod().hasName("getParameter") or
        ma.getMethod().hasName("getParameterValues") or
        ma.getMethod().hasName("getHeader") or
        ma.getMethod().hasName("getHeaders") or
        ma.getMethod().hasName("getQueryString")
      ) and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
      or
      ma.getMethod().hasName("getValue") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie")
      or
      ma.getMethod().hasName("getName") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Part")
      |
      source.asExpr() = ma.getAnArgument()
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("org.apache.commons.io", "FilenameUtils", "getName") and
      sanitizer.asExpr() = ma
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(ConstructorCall cc |
      (cc.getConstructedType().hasQualifiedName("java.io", "File") or
       cc.getConstructedType().hasQualifiedName("java.io", "FileInputStream") or
       cc.getConstructedType().hasQualifiedName("java.io", "FileOutputStream")) and
      sink.asExpr() = cc.getAnArgument()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, ServletPathTraversalConfiguration config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential path traversal vulnerability. User input reaches file operation without proper sanitization."