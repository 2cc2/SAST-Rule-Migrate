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

import codeql.java
import codeql.java.dataflow.TaintTracking
import codeql.java.frameworks.Servlets
import DataFlow::PathGraph
import Field

class HttpParameterSource extends DataFlow::Node {
  HttpParameterSource() {
    exists(MethodAccessExpr ma |
      ma.getMethod().getName() = "getParameter" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asExpr() = ma
    )
  }
}

class ResponseWriterSink extends DataFlow::Node {
  ResponseWriterSink() {
    exists(MethodAccessExpr ma |
      ma.getMethod().getName() = "getWriter" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
      this.asExpr().(MethodAccessExpr).getMethod().getName().matches("%write") and
      this.asExpr() = ma
    )
  }
}

class ServletResponseXSSConfiguration extends TaintTracking::Configuration {
  ServletResponseXSSConfiguration() { this = "ServletResponseXSS" }

  public override predicate isSource(DataFlow::Node source) { source instanceof HttpParameterSource }

  public override predicate isSink(DataFlow::Node sink) { sink instanceof ResponseWriterSink }

  public override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Argument to parameter propagation
    any(DataFlow::ParameterNodeImpl param).readsFrom(pred, succ) or
    // Assignment propagation
    succ.asDefiningExpr() = pred.asExpr() or
    // Field store propagation
    exists(Field f | pred.asExpr() = f.getAnAssignedValue() and succ.asExpr() = f.getAnAccess())
  }
}

from ServletResponseXSSConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlow(source, sink)
select sink, "Cross-site scripting detected in HttpServletResponse writer with variable '$@'. " +
       "User input was detected going directly from the HttpServletRequest into output. " +
       "Ensure your data is properly encoded using org.owasp.encoder.Encode.forHtml: 'Encode.forHtml($@)'.",
       source, "user input"