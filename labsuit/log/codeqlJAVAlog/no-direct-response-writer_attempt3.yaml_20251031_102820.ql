/**
 * @name Detected request with user-input going into OutputStream/Writer
 * @description Potential XSS vulnerability from bypassing view/template escaping
 * @kind path-problem
 * @problem.severity warning
 * @id java/no-direct-response-writer
 * @tags security
 *       external/cwe/cwe-079
 *       external/owasp/a07
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

private class ServletRequestSource extends TaintTracking::Source {
  ServletRequestSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName([
        "getInputStream", "getParameter", "getParameterMap", 
        "getParameterValues", "getReader", "getCookies",
        "getHeader", "getHeaderNames", "getHeaders",
        "getPart", "getParts", "getQueryString"
      ]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
    )
  }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() = any(MethodAccess ma |
      ma.getMethod().hasName([
        "getInputStream", "getParameter", "getParameterMap", 
        "getParameterValues", "getReader", "getCookies",
        "getHeader", "getHeaderNames", "getHeaders",
        "getPart", "getParts", "getQueryString"
      ]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
    )
  }
}

private class ResponseWriterSink extends DataFlow::Node {
  ResponseWriterSink() { 
    exists(MethodAccess ma |
      ma.getMethod().hasName("write") and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "PrintWriter") or
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet", "ServletOutputStream") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "OutputStream")
      )
    )
  }
}

private class HtmlSanitizer extends DataFlow::Node {
  HtmlSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["escapeHtml", "htmlEscape", "encodeForHTML"]) and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.lang", "StringEscapeUtils") or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.web.util", "HtmlUtils") or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.owasp.esapi", "ESAPI")
      )
    )
  }
}

class DirectResponseWriterConfig extends TaintTracking::Configuration {
  DirectResponseWriterConfig() { this = "DirectResponseWriterConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof ServletRequestSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof ResponseWriterSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof HtmlSanitizer
  }
}

from DirectResponseWriterConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected a request with potential user-input going into a OutputStream or Writer object. " +
  "This bypasses any view or template environments, including HTML escaping, which may expose " +
  "this application to cross-site scripting (XSS) vulnerabilities."