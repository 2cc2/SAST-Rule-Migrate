/**
 * @name Cross-site scripting detected in HttpServletResponse writer
 * @description User input was detected going directly from the HttpServletRequest into output.
 * @id servletresponse-writer-xss
 * @kind problem
 * @security-severity 8.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-079
 *       external/owasp/a07_2017
 *       external/owasp/a03_2021
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

class ServletRequestSource extends RemoteFlowSource {
  ServletRequestSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getParameter") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asParameter() = ma.getAnArgument()
    )
  }
}

class ResponseWriterSink extends DataFlow::Node {
  ResponseWriterSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getWriter") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
      this.asExpr() = ma
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
    TaintTracking::localTaintStep(node1, node2) or
    exists(FieldAccess fa | node1.asExpr() = fa.getQualifier() and node2.asExpr() = fa.getAnAccess())
  }
}

from ServletResponseXSSConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Cross-site scripting detected in HttpServletResponse writer with variable $@. " +
  "Ensure your data is properly encoded using org.owasp.encoder.Encode.forHtml: 'Encode.forHtml($@)'.",
  source, source.toString()