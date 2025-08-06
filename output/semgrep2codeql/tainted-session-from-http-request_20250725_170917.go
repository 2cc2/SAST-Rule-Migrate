/**
 * @name Tainted Session from HTTP Request
 * @description Detects input from a HTTPServletRequest going into a session command.
 *              User input into such commands could lead to trust boundary violations
 *              when unvalidated data is trusted.
 * @kind path-problem
 * @problem.severity warning
 * @id java/tainted-session-from-http-request
 * @tags security
 *       external/cwe/cwe-501
 *       external/owasp/a04
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class HttpServletRequestSource extends DataFlow::Node {
  HttpServletRequestSource() {
    exists(Call ma |
      // Direct HttpServletRequest method calls
      (ma.getCallee().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      not ma.getCallee().getName() = "getSession") and
      this.asExpr() = ma
    )
    or
    exists(Call ma |
      // Cookie values
      ma.getCallee().getName() = "getValue" and
      ma.getCallee().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
      this.asExpr() = ma
    )
    or
    exists(MethodAccess ma |
      // Request header decoding
      ma.getCallee().getName() = "decode" and
      ma.getCallee().getDeclaringType().hasQualifiedName("java.net", "URLDecoder") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class SessionSink extends DataFlow::Node {
  SessionSink() {
    exists(MethodAccess ma |
      ma.getCallee().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpSession") and
      (ma.getCallee().getName() = "putValue" or ma.getCallee().getName() = "setAttribute") and
      this.asExpr() = ma.getArgument(1)
    )
  }
}

class SessionTaintConfig extends TaintTracking::Configuration {
  SessionTaintConfig() { this = "SessionTaintConfig" }

  override predicate isSource(DataFlow::Node source) { 
    source instanceof HttpServletRequestSource 
  }

  override predicate isSink(DataFlow::Node sink) { 
    sink instanceof SessionSink 
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) { none() }
}

from SessionTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, 
  "User input from HTTPServletRequest going into session. Validate/sanitize the input before storing in session."