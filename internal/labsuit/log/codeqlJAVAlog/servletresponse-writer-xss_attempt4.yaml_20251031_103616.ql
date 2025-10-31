import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.DataFlow

class ServletRequestSource extends DataFlow::Node {
  ServletRequestSource() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getParameter" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asParameter(ma)
    )
  }
}

class ResponseWriterSink extends DataFlow::Node {
  ResponseWriterSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches(".*\\.write") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
      this = ma.getAnArgument()
    )
  }
}

class AssignmentPropagation extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(AssignExpr ae | pred.asExpr() = ae.getRight() and succ.asExpr() = ae.getLeft())
  }
}

class FieldStorePropagation extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(FieldWrite fw | pred.asExpr() = fw.getValue() and succ.asExpr() = fw.getFieldAccess())
  }
}

module TaintConfig implements TaintTracking::Config {
  override predicate isSource(DataFlow::Node source) { source instanceof ServletRequestSource }
  override predicate isSink(DataFlow::Node sink) { sink instanceof ResponseWriterSink }
  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    any(AssignmentPropagation ap, FieldStorePropagation fp).step(pred, succ)
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where TaintTracking::path(TaintConfig(), source, sink)
select sink, "Cross-site scripting detected in HttpServletResponse writer with variable '$VAR'. " +
  "User input was detected going directly from the HttpServletRequest into output. " +
  "Ensure your data is properly encoded using org.owasp.encoder.Encode.forHtml: 'Encode.forHtml($VAR)'."