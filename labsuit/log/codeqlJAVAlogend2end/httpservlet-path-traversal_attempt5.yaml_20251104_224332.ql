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
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Servlets
import DataFlow::PathGraph

class ServletRequestSource extends TaintTracking::Source {
  ServletRequestSource() {
    exists(MethodAccess ma | 
      ma.getMethod().getName().matches("getParameter%") or
      ma.getMethod().getName().matches("getHeader%") or
      ma.getMethod().getName() = "getQueryString" or
      ma.getMethod().getName() = "getPathInfo" or
      ma.getMethod().getName() = "getServletPath"
    |
      this.asParameter() = ma.getAnArgument()
    ) or
    exists(CookieSource cs | this.asParameter() = cs.asParameter())
  }
}

class CookieSource extends TaintTracking::Source {
  CookieSource() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getValue" and
      ma.getQualifier().getType().hasQualifiedName("javax.servlet.http", "Cookie")
    |
      this.asParameter() = ma.getAnArgument()
    )
  }
}

class FileSink extends TaintTracking::Sink {
  FileSink() {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "File") and
      this.asExpr() = cc.getAnArgument()
    ) or
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "FileInputStream") and
      this.asExpr() = cc.getAnArgument()
    ) or
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "FileOutputStream") and
      this.asExpr() = cc.getAnArgument()
    )
  }
}

class FilenameUtilsSanitizer extends TaintTracking::Sanitizer {
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

  override predicate isSource(TaintTracking::Source source) {
    source instanceof ServletRequestSource
  }

  override predicate isSink(TaintTracking::Sink sink) {
    sink instanceof FileSink
  }

  override predicate isSanitizer(TaintTracking::Sanitizer sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from PathTraversalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential path traversal vulnerability. User-controllable data is used in file operations ($@).",
  source.getNode(), "Untrusted user input"