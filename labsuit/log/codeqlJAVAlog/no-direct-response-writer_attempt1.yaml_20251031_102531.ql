/**
 * @name No direct response writer
 * @description Detected a request with potential user-input going into a OutputStream or Writer object. 
 *              This bypasses any view or template environments, including HTML escaping, which may expose this application 
 *              to cross-site scripting (XSS) vulnerabilities. Consider using a view technology such as JavaServer Faces (JSFs) 
 *              which automatically escapes HTML views.
 * @kind problem
 * @problem.severity warning
 * @id security/no-direct-response-writer
 * @tags security
 *       external/cwe/cwe-79
 *       external/owasp/a07:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class ServletRequestSource extends RemoteFlowSource {
  ServletRequestSource() {
    exists(Method m |
      m.getDeclaringType().getName().matches("javax.servlet.http.HttpServletRequest") and
      m.getName().matches("getInputStream") or
      m.getName().matches("getParameter") or
      m.getName().matches("getParameterMap") or
      m.getName().matches("getParameterValues") or
      m.getName().matches("getReader") or
      m.getName().matches("getCookies") or
      m.getName().matches("getHeader") or
      m.getName().matches("getHeaderNames") or
      m.getName().matches("getHeaders") or
      m.getName().matches("getPart") or
      m.getName().matches("getParts") or
      m.getName().matches("getQueryString")
    )
  }
}

class ResponseWriterSink extends DataFlow::Node {
  ResponseWriterSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().getName().matches("javax.servlet.http.HttpServletResponse") or
       ma.getMethod().getDeclaringType().getName().matches("java.io.PrintWriter") or
       ma.getMethod().getDeclaringType().getName().matches("javax.servlet.ServletOutputStream") or
       ma.getMethod().getDeclaringType().getName().matches("java.io.OutputStream")) and
      ma.getMethod().getName().matches("write")
    )
  }
}

class HtmlSanitizer extends DataFlow::BarrierGuard {
  HtmlSanitizer() {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().getName().matches("org.apache.commons.lang.StringEscapeUtils") or
       ma.getMethod().getDeclaringType().getName().matches("org.springframework.web.util.HtmlUtils") or
       ma.getMethod().getDeclaringType().getName().matches("org.owasp.esapi.ESAPI")) and
      (ma.getMethod().getName().matches("escapeHtml") or
       ma.getMethod().getName().matches("htmlEscape") or
       ma.getMethod().getName().matches("encodeForHTML"))
    )
  }
}

config[DataFlow::Configuration] cfg {
  source = ServletRequestSource()
  sink = ResponseWriterSink()
  isSanitizer = HtmlSanitizer()
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), "Potential XSS vulnerability: user input passed directly to output writer $@.", source.getNode(),
  "User input source"