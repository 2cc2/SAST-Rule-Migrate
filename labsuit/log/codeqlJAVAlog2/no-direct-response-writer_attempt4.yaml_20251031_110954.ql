/**
 * @name Direct response writer with user input
 * @description Detected a request with potential user-input going into a OutputStream or Writer object.
 *              This bypasses any view or template environments, including HTML escaping, which may 
 *              expose this application to cross-site scripting (XSS) vulnerabilities.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id java/no-direct-response-writer
 * @tags security
 *       external/cwe/cwe-079
 *       external/owasp/a07:2017
 *       external/owasp/a03:2021
 */

import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class HttpSource extends DataFlow::Node {
  HttpSource() {
    exists(MethodAccess ma |
      ma.getTarget().hasQualifiedName("javax.servlet.http.HttpServletRequest",
        ["getInputStream", "getParameter", "getParameterMap", "getParameterValues", 
         "getReader", "getCookies", "getHeader", "getHeaderNames", "getHeaders",
         "getPart", "getParts", "getQueryString"]) and
      this.asExpr() = ma
    )
  }
}

class ResponseSink extends DataFlow::Node {
  ResponseSink() {
    exists(MethodAccess ma |
      (ma.getTarget().hasQualifiedName("javax.servlet.http.HttpServletResponse", "write") or
       ma.getTarget().hasQualifiedName("java.io.PrintWriter", "write") or
       ma.getTarget().hasQualifiedName("javax.servlet.ServletOutputStream", "write") or
       ma.getTarget().hasQualifiedName("java.io.OutputStream", "write")) and
      this.asExpr() = ma
    )
  }
}

class HtmlSanitizer extends DataFlow::BarrierGuard {
  HtmlSanitizer() {
    exists(MethodAccess ma |
      (ma.getTarget().hasQualifiedName("org.apache.commons.lang.StringEscapeUtils", "escapeHtml") or
       ma.getTarget().hasQualifiedName("org.springframework.web.util.HtmlUtils", "htmlEscape") or
       ma.getTarget().hasQualifiedName("org.owasp.esapi.ESAPI", "encodeForHTML")) and
      this.asExpr() = ma
    )
  }
}

class DirectResponseWriterConfig extends TaintTracking::Configuration {
  DirectResponseWriterConfig() { this = "Direct Response Writer with User Input" }

  override predicate isSource(DataFlow::Node source) { source instanceof HttpSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof ResponseSink }

  override predicate isSanitizer(DataFlow::BarrierGuard guard) {
    guard instanceof HtmlSanitizer
  }
}

from DirectResponseWriterConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), 
  "Potential XSS vulnerability: user input flows directly to response writer without HTML escaping.",
  source.getNode(), "User input from $@ is written directly to response here.", 
  sink.getNode(), "Response writer call"