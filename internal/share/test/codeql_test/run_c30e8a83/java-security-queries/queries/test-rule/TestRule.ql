/**
 * @name HTTP Response Splitting
 * @description Older Java application servers are vulnerable to HTTP response splitting when CRLF characters 
 *              are injected into HTTP headers from untrusted input.
 * @kind path-problem
 * @problem.severity warning
 * @id java/http-response-splitting
 * @tags security
 *       external/cwe/cwe-113
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class HttpRequestSource extends DataFlow::Node {
  HttpRequestSource() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("getParameter%") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asExpr() = ma
    )
  }
}

class ResponseSink extends DataFlow::Node {
  ResponseSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "addCookie" and 
       ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse")) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class CookieCreation extends DataFlow::Node {
  CookieCreation() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("javax.servlet.http", "Cookie") and
      this.asExpr() = cie.getArgument(1)
    )
  }
}

class ResponseSplittingConfig extends TaintTracking::Configuration {
  ResponseSplittingConfig() { this = "ResponseSplittingConfig" }

  override predicate isSource(DataFlow::Node source) { 
    source instanceof HttpRequestSource 
  }

  override predicate isSink(DataFlow::Node sink) { 
    sink instanceof ResponseSink or
    sink instanceof CookieCreation
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) { none() }
}

from ResponseSplittingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential HTTP response splitting vulnerability from untrusted input"