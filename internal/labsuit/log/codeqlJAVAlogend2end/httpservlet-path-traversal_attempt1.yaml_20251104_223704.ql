/**
 * @name HttpServlet Path Traversal
 * @description Detects potential path traversal vulnerabilities in Java servlets.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-2021-top25
 *       external/cwe/cwe-2022-top25
 *       external/owasp/a01:2021
 *       external/owasp/a05:2017
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Servlets

class ServletPathTraversalConfig extends TaintTracking::Configuration {
  ServletPathTraversalConfig() { this = "ServletPathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      (
        // Source from HttpServletRequest directly
        ma.getMethod().getName() = "getParameter" and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
        or
        // Source from cookies
        exists(MethodAccess getCookies |
          getCookies.getMethod().getName() = "getCookies" and
          getCookies.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
          (
            ma.getMethod().getName() = "getValue" and
            ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
            DataFlow::localFlow(DataFlow::exprNode(getCookies), DataFlow::exprNode(ma))
          )
        )
      ) and
      source.asExpr() = ma
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getName" and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      node.asExpr() = ma
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(ConstructorCall cc |
      (
        cc.getConstructedType().hasQualifiedName("java.io", "FileInputStream")
        or
        cc.getConstructedType().hasQualifiedName("java.io", "FileOutputStream")
      ) and
      sink.asExpr() = cc.getArgument(0)
    )
    or
    exists(VariableAccess va |
      va.getVariable().getType() instanceof TypeFile and
      sink.asExpr() = va
    )
  }
}

from ServletPathTraversalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source.getNode(), "Potential path traversal vulnerability. User input reaches file operation without proper sanitization."