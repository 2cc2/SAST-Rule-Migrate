/**
 * @name Tainted XPath from HTTP Request
 * @description Detected input from a HTTPServletRequest going into a XPath evaluate or compile command.
 *              This could lead to xpath injection if variables passed into the evaluate or compile
 *              commands are not properly sanitized. Xpath injection could lead to unauthorized access
 *              to sensitive information in XML documents.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.8
 * @id java/tainted-xpath-from-http-request
 * @tags security
 *       external/cwe/cwe-643
 *       owasp-a03
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Servlets

class ServletRequestToXPath extends TaintTracking::Configuration {
  ServletRequestToXPath() { this = "ServletRequestToXPath" }

  override predicate isSource(DataFlow::Node source) {
    exists(Call ma |
      ma.getCallee().getDeclaringType() instanceof HttpServletRequest and
      source.asExpr() = ma
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call ma |
      (
        ma.getCallee().getName() = "evaluate" and
        ma.getCallee().getDeclaringType().hasQualifiedName("javax.xml.xpath", "XPath") or
        (
          ma.getCallee().getName() = "compile" and
          ma.getCallee().getDeclaringType().hasQualifiedName("javax.xml.xpath", "XPath") and
          exists(Call evaluateCall |
            evaluateCall.getCallee().getName() = "evaluate" and
            evaluateCall.getQualifier() = ma
          )
        )
      ) and
      sink.asExpr() = ma
    )
  }
}

from ServletRequestToXPath config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source,
  "Potential XPath injection vulnerability due to untrusted input from HTTPServletRequest reaching XPath evaluation."