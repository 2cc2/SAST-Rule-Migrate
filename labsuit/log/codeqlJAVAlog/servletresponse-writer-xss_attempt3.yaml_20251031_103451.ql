/**
 * @name ServletResponse Writer XSS
 * @description Detects cross-site scripting vulnerabilities where user input flows directly from HttpServletRequest into HttpServletResponse writer output
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/servletresponse-writer-xss
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 *       owasp-a3:injection
 */

import java
import codeql.java.dataflow.TaintTracking
import codeql.java.dataflow.FlowSources

class ServletRequestSource extends DataFlow::SourceNode {
  ServletRequestSource() {
    exists(MethodAccess ma | 
      ma.getMethod().hasQualifiedName("javax.servlet.http.HttpServletRequest", "getParameter") |
      this.asParameter(ma.getAnArgument())
    )
  }
}

class ResponseWriterSink extends DataFlow::SinkNode {
  ResponseWriterSink() {
    exists(MethodAccess ma | 
      ma.getMethod().hasQualifiedName("javax.servlet.http.HttpServletResponse", "getWriter") and
      ma.getMethod().getName().matches(".*\.write") and
      this.asExpr(ma.getAnArgument())
    )
  }
}

module TaintConfig implements TaintTracking::Configuration {
  override predicate isSource(DataFlow::SourceNode source) { source instanceof ServletRequestSource }
  override predicate isSink(DataFlow::SinkNode sink) { sink instanceof ResponseWriterSink }

  override predicate isExtensionStep(DataFlow::Node node1, DataFlow::Node node2) {
    TaintTracking::localTaintStep(node1, node2) or
    exists(FieldAccess fa | node1.asExpr() = fa.getQualifier() 
      and node2.asExpr() = fa | 
      TaintTracking::localTaintStep(node1, node2)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where TaintTracking::localPath(new TaintConfig(), source, sink)
select sink, 
  "Cross-site scripting detected in HttpServletResponse writer with variable '$VAR'. " +
  "User input was detected going directly from the HttpServletRequest into output. " +
  "Ensure your data is properly encoded using org.owasp.encoder.Encode.forHtml: 'Encode.forHtml($VAR)'."