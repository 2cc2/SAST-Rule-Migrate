/**
 * @name Detected potential XSS vulnerability due to direct response writing
 * @description Request with potential user-input going into OutputStream or Writer object bypasses view/template environments
 * @kind problem
 * @problem.severity warning
 * @id java/no-direct-response-writer
 * @security-severity 8.0
 * @tags security
 *       external/cwe/cwe-079
 *       owasp-a07:2017
 *       owasp-a03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class HttpSource extends RemoteFlowSource {
  HttpSource() {
    exists(Method m | 
      m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      m.getName() in [
        "getInputStream", "getParameter", "getParameterMap", "getParameterValues", "getReader",
        "getCookies", "getHeader", "getHeaderNames", "getHeaders", "getPart", "getParts", "getQueryString"
      ] and
      this = m.getACall()
    )
  }
}

class ResponseSink extends DataFlow::Node {
  ResponseSink() {
    exists(Method m |
      (
        m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") or
        m.getDeclaringType().hasQualifiedName("java.io", "PrintWriter") or
        m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletOutputStream") or
        m.getDeclaringType().hasQualifiedName("java.io", "OutputStream")
      ) and
      m.getName() = "write" and
      this.asExpr() = m.getACall()
    )
  }
}

class HtmlSanitizer extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Method m |
      (
        m.getDeclaringType().hasQualifiedName("org.apache.commons.lang", "StringEscapeUtils") or
        m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "HtmlUtils") or
        m.getDeclaringType().hasQualifiedName("org.owasp.esapi", "ESAPI")
      ) and
      m.getName() in ["escapeHtml", "htmlEscape", "encodeForHTML"] and
      exists(MethodAccess ma | ma.getMethod() = m | 
        pred.asExpr() = ma.getArgument(0) and
        succ.asExpr() = ma
      )
    )
  }
}

class NoDirectResponseWriterConfig extends TaintTracking::Configuration {
  NoDirectResponseWriterConfig() { this = "NoDirectResponseWriterConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof HttpSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof ResponseSink }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    HtmlSanitizer().step(pred, succ)
  }
}

from NoDirectResponseWriterConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), "Detected request with potential user-input going into OutputStream or Writer object. " +
  "This bypasses view/template environments, potentially exposing to XSS vulnerabilities. " +
  "Consider using view technology like JavaServer Faces which auto-escapes HTML."