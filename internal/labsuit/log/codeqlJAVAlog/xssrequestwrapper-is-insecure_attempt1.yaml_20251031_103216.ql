/**
 * @name XSSRequestWrapper is insecure
 * @description It looks like you're using an implementation of XSSRequestWrapper from dzone.
 *              The XSS filtering in this code is not secure and can be bypassed by malicious actors.
 * @kind problem
 * @problem.severity warning
 * @id java/xssrequestwrapper-is-insecure
 * @tags security
 *       owasp-a07
 *       owasp-a03
 *       cwe-79
 */

import java
import DataFlow::PathGraph

predicate isXSSRequestWrapper(Type t) {
  t.hasName("XSSRequestWrapper") and
  t.getASupertype*().hasQualifiedName("javax.servlet.http", "HttpServletRequestWrapper")
}

predicate isInsecureScriptFilter(MethodAccess ma) {
  ma.getMethod().hasName("compile") and
  ma.getMethod().getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
  ma.getArgument(0).(StringLiteral).getValue() = "</script>"
}

from MethodAccess ma, Type t
where 
  isInsecureScriptFilter(ma) and
  isXSSRequestWrapper(t)
select ma, "Insecure XSS filtering implementation found. $@ inherits from XSSRequestWrapper which uses insecure Pattern.compile('</script>').",
  t, "XSSRequestWrapper declaration"