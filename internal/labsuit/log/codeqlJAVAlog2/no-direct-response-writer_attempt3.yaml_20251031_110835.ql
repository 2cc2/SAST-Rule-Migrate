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

import java
import codeql.java.dataflow.DataFlow
import codeql.java.dataflow.TaintTracking

class HttpSource extends DataFlow::Node {
  HttpSource() {
    exists(MethodAccess ma, Method m |
      m.hasQualifiedName("javax.servlet.http.HttpServletRequest",
        ["getInputStream", "getParameter", "getParameterMap", "getParameterValues", 
         "getReader", "getCookies", "getHeader", "getHeaderNames", "getHeaders",
         "getPart", "getParts", "getQueryString"]) and
      ma.getMethod() = m and
      this.asExpr() = ma
    )
  }

  override predicate isSource(DataFlow::Node source) { this = source }
}

class ResponseSink extends DataFlow::Node {
  ResponseSink() {
    exists(MethodAccess ma, Method m |
      (m.hasQualifiedName("javax.servlet.http.HttpServletResponse", "write") or
       m.hasQualifiedName("java.io.PrintWriter", "write") or
       m.hasQualifiedName("javax.servlet.ServletOutputStream", "write") or
       m.hasQualifiedName("java.io.OutputStream", "write")) and
      ma.getMethod() = m and
      this.asExpr() = ma
    )
  }

  override predicate isSink(DataFlow::Node sink) { this = sink }
}

class HtmlSanitizer extends DataFlow::BarrierGuard {
  HtmlSanitizer() {
    exists(MethodAccess ma, Method m |
      (m.hasQualifiedName("org.apache.commons.lang.StringEscapeUtils", "escapeHtml") or
       m.hasQualifiedName("org.springframework.web.util.HtmlUtils", "htmlEscape") or
       m.hasQualifiedName("org.owasp.esapi.ESAPI", "encodeForHTML")) and
      ma.getMethod() = m and
      this.asExpr() = ma
    )
  }

  override predicate allowsBarrier(DataFlow::Barrier barrier) { this = barrier }
}

class DirectResponseWriterConfig extends TaintTracking::Configuration {
  DirectResponseWriterConfig() { this = "Direct Response Writer with User Input" }

  override predicate isSource(DataFlow::Node source) { any(HttpSource s).isSource(source) }

  override predicate isSink(DataFlow::Node sink) { any(ResponseSink s).isSink(sink) }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    none() // No additional taint steps needed for this rule
  }

  override predicate isBarrierGuard(DataFlow::BarrierGuard guard) {
    any(HtmlSanitizer hs).allowsBarrier(guard)
  }
}

from DirectResponseWriterConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), 
  "Potential XSS vulnerability: user input flows directly to response writer without HTML escaping.",
  source.getNode(), "User input from $@ is written directly to response here.", 
  sink.getNode(), "Response writer call"