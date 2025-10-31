/**
 * @name No direct Response Writer
 * @description Detected a request with potential user-input going into an OutputStream or Writer object.
 * @kind problem
 * @precision high
 * @id java/no-direct-response-writer
 * @severity warning
 */

import java
import DataFlow
import TaintTracking
import semmle.code.java.StringFormat

class ServletRequestSource extends TaintTracking::Source {

  ServletRequestSource() { 
    exists(MethodAccess ma |
      ma.getMethod().hasName([
        "getInputStream", "getParameter", "getParameterMap", "getParameterValues",
        "getReader", "getCookies", "getHeader", "getHeaderNames", "getHeaders",
        "getPart", "getParts", "getQueryString"
      ]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
    )
  }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      source.asExpr() = ma and
      ma.getMethod().hasName([
        "getInputStream", "getParameter", "getParameterMap", "getParameterValues",
        "getReader", "getCookies", "getHeader", "getHeaderNames", "getHeaders",
        "getPart", "getParts", "getQueryString"
      ]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
    )
  }
}

class ResponseWriterSink extends TaintTracking::Sink {
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

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      sink.asExpr() = ma and
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

class HtmlSanitizer extends TaintTracking::Sanitizer {
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

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodAccess ma |
      sanitizer.asExpr() = ma and
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

  override predicate isSource(DataFlow::Node source) {
    any(ServletRequestSource s).isSource(source)
  }

  override predicate isSink(DataFlow::Node sink) {
    any(ResponseWriterSink s).isSink(sink)
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    any(HtmlSanitizer s).isSanitizer(sanitizer)
  }
}

from DataFlow::Node source, DataFlow::Node sink, DirectResponseWriterConfig config
where config.hasFlow(source, sink)
select sink, 
  "Detected a request with potential user-input going into an OutputStream or Writer object. " +
  "This bypasses any view or template environments, including HTML escaping, which may expose " +
  "this application to cross-site scripting (XSS) vulnerabilities. Consider using a view " +
  "technology such as JavaServer Faces (JSFs) which automatically escapes HTML views."