/**
 * @name LDAP Injection
 * @description Detected non-constant data passed into an LDAP query. If this data can be
 * controlled by an external user, this is an LDAP injection.
 * Ensure data passed to an LDAP query is not controllable; or properly sanitize
 * the data.
 * @kind problem
 * @problem.severity warning
 * @id java/ldap-injection
 * @tags security
 *       cwe/90
 *       owasp/a01
 *       owasp/a03
 */

import java
import semmle.code.java.dataflow.FlowSources

class LDAPContextCreation extends MethodAccess {
  LDAPContextCreation() {
    exists(Method m | 
      this.getMethod().getName() in ["InitialDirContext", "DirContext", "InitialLdapContext", 
                                     "LdapContext", "LdapCtx", "EventDirContext"] and
      this.getEnclosingCallable() = m
    )
  }

  Method getDeclaringMethod() { result = this.getEnclosingCallable() }
}

class SearchMethodCall extends MethodAccess {
  SearchMethodCall() {
    this.getMethod().getName() = "search" and
    this.getMethod().getDeclaringType().getName() in ["InitialDirContext", "DirContext", 
                                                   "InitialLdapContext", "LdapContext", 
                                                   "LdapCtx", "EventDirContext"]
  }

  Expr getInputParameter() { result = this.getArgument(1) }
}

from Method m, LDAPContextCreation ctx, SearchMethodCall search, Expr input
where
  ctx.getDeclaringMethod() = m and
  search.getMethod().getDeclaringType() = ctx.getMethod().getDeclaringType() and
  input = search.getInputParameter() and
  not input instanceof StringLiteral
select search, "Potential LDAP Injection vulnerability. Ensure input to LDAP query is properly sanitized."