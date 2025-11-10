/**
 * @name Tainted LDAP input from HTTP request
 * @description Detected input from a HttpServletRequest going into an LDAP query.
 *              This could lead to LDAP injection if the input is not properly sanitized,
 *              which could result in attackers modifying objects in the LDAP tree structure.
 *              Ensure data passed to an LDAP query is not controllable or properly sanitize
 *              the data.
 * @kind path-problem
 * @problem.severity warning
 * @id java/tainted-ldapi-from-http-request
 * @tags security
 *       external/cwe/cwe-90
 *       owasp-a01:2017
 *       owasp-a03:2021
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Servlets

class LDAPInjectionConfig extends TaintTracking::Configuration {
  LDAPInjectionConfig() { this = "LDAPInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType() instanceof HttpServletRequest and
      source.asExpr() = ma  // Source is any method call on HttpServletRequest
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "search" and
       ma.getMethod().getDeclaringType().hasQualifiedName("javax.naming.directory", "InitialDirContext")) or
      (ma.getMethod().getName() = "search" and
       ma.getMethod().getDeclaringType().hasQualifiedName("javax.naming.directory", "DirContext")) and
      not ma.getArgument(1).(StringLiteral).getValue().regexpMatch("\\.\\.\\.") and
      sink.asExpr() = ma.getArgument(0)
    )
  }
}

from LDAPInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink,
  "Potential LDAP injection from HTTP request. Ensure input is properly sanitized before use in LDAP queries."