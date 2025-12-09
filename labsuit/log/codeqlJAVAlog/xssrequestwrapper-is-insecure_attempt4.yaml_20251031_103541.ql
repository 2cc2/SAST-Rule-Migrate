/**
 * @name Insecure XSSRequestWrapper usage
 * @description Detection of insecure XSSRequestWrapper implementation
 * @kind problem
 * @id java/xss-request-wrapper
 * @tags security
 *   external/cwe/cwe-079
 *   external/owasp/a03
 *   external/owasp/a07
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.frameworks.Servlets

class XSSRequestWrapper extends Class {
  XSSRequestWrapper() {
    this.hasQualifiedName("", "XSSRequestWrapper") and
    this.getASupertype() instanceof TypeHttpServletRequestWrapper
  }
}

class InsecureScriptFilter extends MethodAccess {
  InsecureScriptFilter() {
    this.getMethod().hasName("compile") and
    this.getMethod().getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
    this.getArgument(0).(Literal).getValue().toString() = "</script>"
  }
}

from XSSRequestWrapper wrapper, InsecureScriptFilter filter
select wrapper, "Using insecure XSSRequestWrapper implementation that can be bypassed. " +
  "Consider using automatic escaping in view templates instead of manual filtering."