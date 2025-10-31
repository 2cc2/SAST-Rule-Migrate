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

import codeql.java.dataflow.DataFlow
import codeql.java.dataflow.TaintTracking

class HttpSource extends DataFlow::Node2 {
  HttpSource() {
    exists(Method m |
      m.hasQualifiedName("javax.servlet.http.HttpServletRequest",
        ["getInputStream", "getParameter", "getParameterMap", "getParameterValues", 
         "getReader", "getCookies", "getHeader", "getHeaderNames", "getHeaders",
         "getPart", "getParts", "getQueryString"]) and
      this.asParameter() = m.getACall()
    )
  }
}

class ResponseSink extends DataFlow::Node2 {
  ResponseSink() {
    exists(Method m |
      (m.hasQualifiedName("javax.servlet.http.HttpServletResponse", "write") or
       m.hasQualifiedName("java.io.PrintWriter", "write") or
       m.hasQualifiedName("javax.servlet.ServletOutputStream", "write") or
       m.hasQualifiedName("java.io.OutputStream", "write")) and
      this.asParameter() = m.getACall()
    )
  }
}

class HtmlSanitizer extends DataFlow::BarrierGuard {
  HtmlSanitizer() {
    exists(Method m |
      (m.hasQualifiedName("org.apache.commons.lang.StringEscapeUtils", "escapeHtml") or
       m.hasQualifiedName("org.springframework.web.util.HtmlUtils", "htmlEscape") or
       m.hasQualifiedName("org.owasp.esapi.ESAPI", "encodeForHTML")) and
      this.asParameter() = m.getACall()
    )
  }
}

class DirectResponseWriterConfig extends TaintTracking::Configuration2 {
  DirectResponseWriterConfig() { this = "Direct Response Writer with User Input" }

  override predicate isSource(DataFlow::Node2 source) { source instanceof HttpSource }

  override predicate isSink(DataFlow::Node2 sink) { sink instanceof ResponseSink }

  override predicate isSanitizer(DataFlow::BarrierGuard guard) {
    guard instanceof HtmlSanitizer
  }
}

from DirectResponseWriterConfig config, DataFlow::PathNode2 source, DataFlow::PathNode2 sink
where config.hasFlowPath(source, sink)
select sink.getNode(), 
  "Potential XSS vulnerability: user input flows directly to response writer without HTML escaping.",
  source.getNode(), "User input from $@ is written directly to response here.", 
  sink.getNode(), "Response writer call"