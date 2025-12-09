/**
 * @name Insecure XSSRequestWrapper usage
 * @description Detects usage of XSSRequestWrapper implementation from dzone article
 * @kind problem
 * @id java/xssrequestwrapper-is-insecure
 * @tags security
 *   external/cwe/cwe-079
 *   external/owasp/a03
 *   external/owasp/a07
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.frameworks.Servlets

class XSSRequestWrapper extends RefType {
  XSSRequestWrapper() {
    this.hasName("XSSRequestWrapper") and
    this.getASupertype() instanceof TypeHttpServletRequestWrapper
  }
}

class InsecureScriptFilter extends DataFlow::Node {
  InsecureScriptFilter() {
    exists(MethodAccess call |
      call.getMethod().getName() = "compile" and
      call.getMethod().getDeclaringType().getName() = "Pattern" and
      exists(Expr arg |
        arg = call.getArgument(0) and
        arg.getStringValue() = "</script>"
      )
    )
  }
}

from XSSRequestWrapper wrapper, InsecureScriptFilter filter
select wrapper, "Insecure XSSRequestWrapper usage that can be bypassed by malicious actors. " +
  "Recommend using automatic escaping in views/templates instead."