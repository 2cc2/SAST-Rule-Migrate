/**
 * @name Direct Response Writer Detection
 * @description Detects request with potential user-input going into OutputStream or Writer
 * @id no-direct-response-writer
 * @kind path-problem
 * @severity warning
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class ServletRequestSource extends DataFlow::Node {
  ServletRequestSource() { 
    exists(MethodAccess ma |
      ma.getMethod().hasName([
        "getInputStream", "getParameter", "getParameterMap", 
        "getParameterValues", "getReader", "getCookies", "getHeader",
        "getHeaderNames", "getHeaders", "getPart", "getParts", "getQueryString"
      ]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asExpr() = ma
    )
  }
}

class ResponseWriterSink extends DataFlow::Node {
  ResponseWriterSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("write") and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "PrintWriter") or
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet", "ServletOutputStream") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "OutputStream")
      ) and
      this.asExpr() = ma
    )
  }
}

class HtmlSanitizer extends DataFlow::Node {
  HtmlSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["escapeHtml", "htmlEscape", "encodeForHTML"]) and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.lang", "StringEscapeUtils") or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.web.util", "HtmlUtils") or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.owasp.esapi", "ESAPI")
      ) and
      this.asExpr() = ma
    )
  }
}

class DirectResponseWriterConfig extends TaintTracking::Configuration {
  DirectResponseWriterConfig() { this = "DirectResponseWriterConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ServletRequestSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ResponseWriterSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof HtmlSanitizer
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, DirectResponseWriterConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), 
  "Potential XSS vulnerability: user input flows directly into response writer without HTML escaping", 
  source.getNode(), "User input originates here"