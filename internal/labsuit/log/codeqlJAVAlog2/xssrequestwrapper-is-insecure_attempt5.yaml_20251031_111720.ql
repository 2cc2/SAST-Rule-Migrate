/**
 * @name XSSRequestWrapper is insecure
 * @description It looks like you're using an implementation of XSSRequestWrapper from dzone. 
 * The XSS filtering in this code is not secure and can be bypassed by malicious actors. 
 * It is recommended to use a stack that automatically escapes in your view or templates instead of filtering yourself.
 * @kind problem
 * @problem.severity warning
 * @id java/xssrequestwrapper-is-insecure
 * @tags security
 *       external/cwe/cwe-079
 *       external/owasp/a03:2021
 *       external/owasp/a07:2017
 */

import java

class XSSRequestWrapperType extends RefType {
  XSSRequestWrapperType() { 
    this.getName() = "XSSRequestWrapper" and
    this.getASupertype().getName() = "HttpServletRequestWrapper"
  }
}

class InsecurePatternCompileCall extends MethodAccess {
  InsecurePatternCompileCall() {
    this.getMethod().getName() = "compile" and
    this.getMethod().getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
    this.getArgument(0).toString() = "\"</script>\""
  }
}

from InsecurePatternCompileCall call
where exists(XSSRequestWrapperType t)
select call, "Insecure XSS filtering detected. The XSSRequestWrapper implementation can be bypassed. " +
  "Use automatic escaping in views/templates instead (references: " +
  "https://owasp.org/Top10/A03_2021-Injection, " +
  "https://find-sec-bugs.github.io/bugs.htm#XSS_REQUEST_WRAPPER)"