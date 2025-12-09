/**
 * @name xssrequestwrapper-is-insecure
 * @kind problem
 * @id java/xssrequestwrapper-is-insecure
 * @severity Warning
 * @security-severity 7.5
 * @precision medium
 * @tags security
 *       owasp-a07
 *       owasp-a03
 *       cwe-79
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.security.XSS

class XSSRequestWrapperType extends RefType {
  XSSRequestWrapperType() {
    this.hasQualifiedName("", "XSSRequestWrapper")
  }
}

class InsecurePatternCompileCall extends MethodAccess {
  InsecurePatternCompileCall() {
    exists(Method m | m = this.getMethod() |
      m.hasName("compile") and
      m.getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
      this.getArgument(0).(Literal).getValue() = "</script>"
    )
  }
}

from XSSRequestWrapperType t, InsecurePatternCompileCall call
select call, 
  "It looks like you're using an implementation of XSSRequestWrapper from dzone. " +
  "(https://www.javacodegeeks.com/2012/07/anti-cross-site-scripting-xss-filter.html) " +
  "The XSS filtering in this code is not secure and can be bypassed by malicious actors. " +
  "It is recommended to use a stack that automatically escapes in your view or templates instead of filtering yourself."