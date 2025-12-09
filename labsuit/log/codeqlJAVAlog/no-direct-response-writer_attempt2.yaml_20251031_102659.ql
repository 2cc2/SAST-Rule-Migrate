/**
 * @name Direct response writer without HTML escaping
 * @description Detected a request with potential user-input going into a OutputStream or Writer object.
 * @kind problem
 * @problem.severity warning
 * @id java/no-direct-response-writer
 * @tags security
 *       external/cwe/cwe-079
 *       owasp-a07:2017
 *       owasp-a03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

private class ServletRequestSource extends RemoteFlowSource::Source {
  ServletRequestSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName([
        "getInputStream", "getParameter", "getParameterMap", "getParameterValues",
        "getReader", "getCookies", "getHeader", "getHeaderNames", "getHeaders",
        "getPart", "getParts", "getQueryString"
      ]) and
      ma.getMethod().getDeclaringType().getQualifiedName() = "javax.servlet.http.HttpServletRequest" and
      this.asExpr() = ma
    )
  }
}

private class ResponseWriterSink extends DataFlow::Node {
  ResponseWriterSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().hasName("write") and
        ma.getMethod().getDeclaringType().getQualifiedName().matches(
          "javax.servlet.http.HttpServletResponse|java.io.PrintWriter|javax.servlet.ServletOutputStream|java.io.OutputStream"
        )
      ) and
      this.asExpr() = ma
    )
  }
}

private class HtmlSanitizer extends DataFlow::Node {
  HtmlSanitizer() {
    exists(MethodAccess ma |
      (
        ma.getMethod().hasName(["escapeHtml", "htmlEscape", "encodeForHTML"]) and
        ma.getMethod().getDeclaringType().getQualifiedName().matches(
          "org.apache.commons.lang.StringEscapeUtils|org.springframework.web.util.HtmlUtils|org.owasp.esapi.ESAPI"
        )
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

from DataFlow::Node source, DataFlow::Node sink
where any(DirectResponseWriterConfig cfg).hasFlow(source, sink)
select sink, "Detected a request with potential user-input going into a OutputStream or Writer object. " +
  "This bypasses any view or template environments, including HTML escaping, " +
  "which may expose this application to cross-site scripting (XSS) vulnerabilities. " +
  "Consider using a view technology such as JavaServer Faces (JSFs) which automatically escapes HTML views."