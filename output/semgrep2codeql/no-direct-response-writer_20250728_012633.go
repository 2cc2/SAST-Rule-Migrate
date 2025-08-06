/**
 * @name Direct Response Writer
 * @description Detected a request with potential user-input going into an OutputStream 
 *              or Writer object, which may expose cross-site scripting (XSS) vulnerabilities.
 * @kind path-problem
 * @problem.severity warning
 * @id java/no-direct-response-writer
 * @tags security
 *       external/cwe/cwe-79
 *       external/owasp/a07
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class ServletSources extends DataFlow::Node {
  ServletSources() {
    exists(MethodAccess ma |
      ma.getCallee().getName().matches("getInputStream|getParameter|getParameterMap|" +
        "getParameterValues|getReader|getCookies|getHeader|getHeaderNames|" +
        "getHeaders|getPart|getParts|getQueryString") and
      (ma.getCallee().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") or
       ma.getCallee().getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest")) and
      this.asExpr() = ma
    )
  }
}

class ResponseSink extends DataFlow::Node {
  ResponseSink() {
    exists(MethodAccess ma |
      (ma.getCallee().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
       ma.getCallee().getName().matches("getWriter|getOutputStream")) or
      (ma.getCallee().getDeclaringType().hasQualifiedName("java.io", "PrintWriter") and
       ma.getCallee().getName().matches("print|println|write|append")) or
      (ma.getCallee().getDeclaringType().hasQualifiedName("javax.servlet", "ServletOutputStream") and
       ma.getCallee().getName().matches("print|println|write")) or
      (ma.getCallee().getDeclaringType().hasQualifiedName("java.io", "OutputStream") and
       ma.getCallee().getName() = "write") and
      this.asExpr() = ma
    )
  }
}

class Sanitizers extends DataFlow::Node {
  Sanitizers() {
    exists(MethodAccess ma |
      ma.getCallee().getName().matches("forHtml|sanitize|scan|clean|escapeHtml|htmlEscape|encodeForHTML") and
      (ma.getCallee().getDeclaringType().hasQualifiedName("org.owasp", "*.Encoder") or
       ma.getCallee().getDeclaringType().hasQualifiedName("org.owasp", "*.PolicyFactory") or
       ma.getCallee().getDeclaringType().hasQualifiedName("org.owasp", "*.AntiSamy") or
       ma.getCallee().getDeclaringType().hasQualifiedName("org.jsoup", "JSoup") or
       ma.getCallee().getDeclaringType().hasQualifiedName("org.apache.commons.lang", "StringEscapeUtils") or
       ma.getCallee().getDeclaringType().hasQualifiedName("org.springframework.web.util", "HtmlUtils") or
       ma.getCallee().getDeclaringType().hasQualifiedName("org.owasp.esapi", "ESAPI")) and
      this.asExpr() = ma
    )
  }
}

class DirectResponseConfig extends TaintTracking::Configuration {
  DirectResponseConfig() { this = "DirectResponseConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof ServletSources }

  override predicate isSink(DataFlow::Node sink) { sink instanceof ResponseSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) { sanitizer instanceof Sanitizers }
}

from DirectResponseConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential XSS vulnerability: user input flows directly to response writer"