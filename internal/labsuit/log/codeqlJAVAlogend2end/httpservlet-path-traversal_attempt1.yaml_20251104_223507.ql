/**
 * @name HttpServlet Path Traversal
 * @description Detected a potential path traversal. A malicious actor could control the location 
 *              of this file, to include going backwards in the directory with '../'.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/path-traversal
 * @tags security
 *       cwe/cwe-22
 *       owasp/a01
 *       owasp/a05
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Servlets
import DataFlow::PathGraph

class ServletRequestSource extends RemoteFlowSource {
  ServletRequestSource() {
    exists(MethodAccess ma | 
      ma.getMethod().getDeclaringType() instanceof HttpServletRequest |
      this.asExpr() = ma
    )
    or
    exists(CookieGetValueCall cgvc | this.asExpr() = cgvc)
  }
}

class CookieGetValueCall extends MethodAccess {
  CookieGetValueCall() {
    this.getMethod().getName() = "getValue" and
    this.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie")
  }
}

class PathTraversalSink extends DataFlow::Node {
  PathTraversalSink() {
    exists(ConstructorCall cc | 
      cc.getConstructedType().hasQualifiedName("java.io", "FileInputStream") 
      and this.asExpr() = cc.getAnArgument()
    )
    or
    exists(VariableAccess va |
      va.getVariable().getType().hasQualifiedName("java.io", "File") 
      and this.asExpr() = va
    )
    or
    exists(VariableAccess va |
      va.getVariable().getType().hasQualifiedName("java.io", "FileOutputStream")
      and this.asExpr() = va
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::BarrierGuard {
  FilenameUtilsSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getName" and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils")
    )
  }
}

class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() { this = "PathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ServletRequestSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof PathTraversalSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }
}

from PathTraversalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink,
  "Potential path traversal vulnerability. User input may control file paths ($@).",
  source.getNode(), "user input"