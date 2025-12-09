/**
 * @name ServletResponse Writer XSS
 * @description Detects cross-site scripting in HttpServletResponse writer.
 * @kind path-problem
 * @problem.severity error
 * @id java/servletresponse-writer-xss
 * @tags security
 *       cwe/cwe-79
 *       owasp/a07:2017
 *       owasp/a03:2021
 */

import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Servlets
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.Field
import semmle.code.java.MethodAccess

class HttpParameterSource extends DataFlow::Node {
  HttpParameterSource() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getParameter" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asExpr() = ma
    )
  }
}

class ResponseWriterSink extends DataFlow::Node {
  ResponseWriterSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getWriter" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
      ma.getQualifier().(MethodAccess).getMethod().getName().matches("%write") and
      this.asExpr() = ma
    )
  }
}

class ServletResponseXSSConfiguration extends TaintTracking::Configuration {
  ServletResponseXSSConfiguration() { this = "ServletResponseXSS" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof HttpParameterSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ResponseWriterSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DataFlow::ParameterNode param | param.readsFrom(pred, succ)) or
    succ.asDefiningExpr() = pred.asExpr() or
    exists(Field f | pred.asExpr() = f.getAnAssignedValue() and succ.asExpr() = f.getAnAccess())
  }
}

from ServletResponseXSSConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Cross-site scripting detected in HttpServletResponse writer with variable '$@'. " +
       "User input was detected going directly from the HttpServletRequest into output. " +
       "Ensure your data is properly encoded using org.owasp.encoder.Encode.forHtml: 'Encode.forHtml($@)'.",
       source, "user input"