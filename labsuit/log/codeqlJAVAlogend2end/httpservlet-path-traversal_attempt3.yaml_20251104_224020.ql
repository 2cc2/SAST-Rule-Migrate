/**
 * @name HttpServlet Path Traversal
 * @description Detects path traversal vulnerabilities in Java servlets where user-controlled
 *              input can manipulate file system paths.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-073
 *       owasp-a05:2017
 *       owasp-a01:2021
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Servlets
import DataFlow::PathGraph

class ServletRequestSource extends DataFlow::SourceNode {
  ServletRequestSource() {
    exists(MethodAccess ma | 
      ma.getMethod().getName() matches "getParameter%" or
      ma.getMethod().getName() matches "getHeader%" or
      ma.getMethod().getName() matches "getQueryString" or
      ma.getMethod() = getPathInfo() or
      ma.getMethod() = getServletPath()
    |
      this.asExpr() = ma
    ) or
    exists(CookieSource cs | this.asExpr() = cs.asExpr())
  }
}

class CookieSource extends DataFlow::SourceNode {
  CookieSource() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getValue" and
      ma.getQualifier().getType().hasName("javax.servlet.http.Cookie")
    |
      this.asExpr() = ma
    )
  }
}

class FileSink extends DataFlow::SinkNode {
  FileSink() {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "File") and
      this.asExpr() = cc.getArgument(0)
    ) or
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") and
      this.asExpr() = ma.getArgument(0)
    ) or
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "FileInputStream") and
      this.asExpr() = cc.getArgument(0)
    ) or
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "FileOutputStream") and
      this.asExpr() = cc.getArgument(0)
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::BarrierNode {
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
    source instanceof ServletRequestSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from PathTraversalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential path traversal vulnerability. User-controllable data is used in file operations ($@).",
  source.getNode(), "Untrusted user input"