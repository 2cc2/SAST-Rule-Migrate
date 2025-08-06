/**
 * @name ServletResponse writer XSS
 * @description Detects cross-site scripting in HttpServletResponse writer where user input from HttpServletRequest
 *              is directly written to output without proper encoding.
 * @kind path-problem
 * @problem.severity error
 * @id java/servlet-response-writer-xss
 * @tags security
 *       external/cwe/cwe-79
 *       external/owasp/a07:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class ServletResponseWriterXssConfig extends TaintTracking::Configuration {
  ServletResponseWriterXssConfig() { this = "ServletResponseWriterXssConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getParameter" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      source.asExpr() = ma
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "write" and ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "PrintWriter")) or
      (ma.getMethod().getName() = "println" and ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "PrintWriter"))
      and
      sink.asExpr() = ma.getAnArgument()
    )
  }
}

from ServletResponseWriterXssConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink,
  "Cross-site scripting detected in HttpServletResponse writer. User input from HttpServletRequest flows directly to output without proper encoding. Use org.owasp.encoder.Encode.forHtml to encode data."