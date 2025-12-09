/** 
 * @name Cross-site scripting in HttpServletResponse writer
 * @description Detection of unencoded user input written directly to HTTP response
 * @kind path-problem
 * @id java/servletresponse-writer-xss
 * @security-severity 9.0
 * @problem.severity error
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

class ServletRequestSource extends RemoteFlowSource {
  ServletRequestSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getParameter") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asExpr() = ma
    )
  }
}

class ResponseWriterSink extends DataFlow::Node {
  ResponseWriterSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getWriter") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
      ma.getQualifier().getType() instanceof TypeName and
      ma.getQualifier().getType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
      this.asExpr() = ma
    )
  }
}

class TaintTrackingConfig extends TaintTracking::Configuration {
  TaintTrackingConfig() { this = "ServletResponseWriterXssConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ServletRequestSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ResponseWriterSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Handle argument to parameter propagation
    exists(MethodAccess ma |
      ma.getAnArgument() = pred.asExpr() and
      succ.asExpr() = ma
    )
    or
    // Handle assignment propagation
    exists(AssignExpr assign |
      assign.getRValue() = pred.asExpr() and
      assign.getLValue() = succ.asExpr()
    )
    or
    // Handle field store propagation
    exists(FieldWrite fw |
      fw.getRValue() = pred.asExpr() and
      fw.getLValue() = succ.asExpr()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintTrackingConfig config
where config.hasFlowPath(source, sink)
select sink, "Cross-site scripting detected in HttpServletResponse writer with variable. User input was detected going directly from the HttpServletRequest into output. Ensure your data is properly encoded using org.owasp.encoder.Encode.forHtml"