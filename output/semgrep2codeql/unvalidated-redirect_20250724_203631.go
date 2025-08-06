/**
 * @name Unvalidated Redirect
 * @description Application redirects to a destination URL specified by a user-supplied
 *    parameter that is not validated. This could direct users to malicious locations.
 *    Consider using an allowlist to validate URLs.
 * @kind path-problem
 * @problem.severity warning
 * @id java/unvalidated-redirect
 * @tags security
 *    external/cwe/cwe-601
 *    external/owasp/a01
 *    external/asvs/V5.1.5
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Servlets

class UnvalidatedRedirectConfig extends TaintTracking::Configuration {
  UnvalidatedRedirectConfig() { this = "UnvalidatedRedirectConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "sendRedirect" and
      ma.getMethod().getDeclaringType().getName() = "HttpServletResponse" and
      sink.asExpr() = ma.getArgument(0)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().getName() = "addHeader" and
      ma.getMethod().getDeclaringType().getName() = "HttpServletResponse" and
      ma.getArgument(0).(StringLiteral).getValue() = "Location" and
      sink.asExpr() = ma.getArgument(1)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, UnvalidatedRedirectConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Unvalidated redirect to $@.", source.getNode(),
  "User-provided URL"