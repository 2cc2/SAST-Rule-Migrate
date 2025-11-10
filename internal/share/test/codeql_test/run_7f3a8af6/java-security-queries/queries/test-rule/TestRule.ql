/**
 * @name Anonymous LDAP Bind
 * @description Detects anonymous LDAP bind which permits anonymous users to execute LDAP statements.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/anonymous-ldap-bind
 * @tags security
 *       external/cwe/cwe-287
 *       external/owasp/a02:2017
 *       external/owasp/a07:2021
 */

import java
import semmle.code.java.dataflow.DataFlow

class AnonymousLdapBindConfig extends DataFlow::Configuration {
  AnonymousLdapBindConfig() { this = "AnonymousLdapBindConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess put |
      put.getMethod().getName() = "put" and
      put.getArgument(1).toString() = "\"none\"" and
      source.asExpr() = put.getArgument(0)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(ClassInstanceExpr init |
      init.getConstructedType().hasQualifiedName("javax.naming", "InitialDirContext") and
      sink.asExpr() = init.getArgument(0)
    )
  }
}

from AnonymousLdapBindConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source.getNode(), 
  "Detected anonymous LDAP bind. This permits anonymous users to execute LDAP statements. Consider enforcing authentication."