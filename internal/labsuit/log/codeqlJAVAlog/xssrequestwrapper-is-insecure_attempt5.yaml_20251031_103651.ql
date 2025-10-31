/**
 * @name Insecure XSSRequestWrapper detection
 * @description Detects usage of insecure XSSRequestWrapper implementation from dzone article
 * @kind problem
 * @id java/xssrequestwrapper-is-insecure
 * @severity Warning
 * @tags security
 *       owasp-a7
 *       owasp-a3
 *       cwe-79
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.frameworks.Servlets

class XSSRequestWrapper extends RefType {
  XSSRequestWrapper() {
    this.hasQualifiedName("", "XSSRequestWrapper") and
    this.getDeclaringType().getType().hasQualifiedName(
      "javax.servlet.http",
      "HttpServletRequestWrapper"
    )
  }
}

class InsecureScriptFilter extends MethodAccess {
  InsecureScriptFilter() {
    this.getMethod().hasQualifiedName("java.util.regex.Pattern", "compile") and
    this.getArgument(0).toStringLiteral().getValue() = "</script>"
  }
}

from XSSRequestWrapper xssWrapper, InsecureScriptFilter filter
select xssWrapper, "This XSSRequestWrapper implementation is insecure and can be bypassed. " +
  "Use automatic escaping in your view/templates instead of manual filtering."