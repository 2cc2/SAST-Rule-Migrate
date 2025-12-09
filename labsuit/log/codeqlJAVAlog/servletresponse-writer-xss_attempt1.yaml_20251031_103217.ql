/**
 * @name ServletResponse writer XSS
 * @description Cross-site scripting detected in HttpServletResponse writer with variable '$VAR'. 
 *   User input was detected going directly from the HttpServletRequest into output. 
 *   Ensure your data is properly encoded using org.owasp.encoder.Encode.forHtml: 'Encode.forHtml($VAR)'.
 * @kind problem
 * @severity error
 * @id servletresponse-writer-xss
 * @tags security
 *       cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
 *       owasp: "A07:2017"
 *       owasp: "A03:2021"
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

class ServletRequestSource extends DataFlow::Source {
  ServletRequestSource() { 
    exists(MethodAccess ma |
      ma.getMethod().hasName("getParameter") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
    )
  }
}

class ResponseWriterSink extends DataFlow::Sink {
  ResponseWriterSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getWriter") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
      ma.getCaller().toString().matches("%write%")
    )
  }
}

class ServletResponseXSSConfig extends TaintTracking::Configuration {
  ServletResponseXSSConfig() { this = "ServletResponseXSSConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ServletRequestSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ResponseWriterSink
  }

  override predicate isExtensionStep(DataFlow::Node node1, DataFlow::Node node2) {
    TaintTracking::localTaintStep(node1, node2) or     // arg->param and assignment
    TaintTracking::fieldWriteStep(node1, node2)        // field-store
  }
}

from ServletResponseXSSConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), "Cross-site scripting detected in HttpServletResponse writer with variable '$VAR'. " +
  "User input was detected going directly from the HttpServletRequest into output. " +
  "Ensure your data is properly encoded using org.owasp.encoder.Encode.forHtml: 'Encode.forHtml($VAR)'."