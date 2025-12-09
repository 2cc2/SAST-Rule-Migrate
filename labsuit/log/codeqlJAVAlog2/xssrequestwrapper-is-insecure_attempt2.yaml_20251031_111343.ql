/**
 * @name xssrequestwrapper-is-insecure
 * @kind problem
 * @id python/xssrequestwrapper-is-insecure
 * @severity Warning
 * @security-severity 7.5
 * @precision medium
 * @tags security
 *       owasp-a07
 *       owasp-a03
 *       cwe-79
 */
import python
import semmle.python.security.dataflow.TaintTracking
import semmle.python.web.Security

class XSSRequestWrapperType extends Class {
  XSSRequestWrapperType() {
    this.getDeclaringFile().getBaseName() = "XSSRequestWrapper" and
    this.getName() = "XSSRequestWrapper"
  }
}

class InsecurePatternCompileCall extends Call {
  InsecurePatternCompileCall() {
    exists(Function f | 
      f = this.getTarget() |
      f.getName() = "compile" and
      f.getDeclaringModule().getName() = "re" and
      this.getArgument(0).getStringValue() = "</script>"
    )
  }
}

from XSSRequestWrapperType t, InsecurePatternCompileCall call
select call,
  "It looks like you're using an implementation of XSSRequestWrapper from dzone. " +
  "(https://www.javacodegeeks.com/2012/07/anti-cross-site-scripting-xss-filter.html) " +
  "The XSS filtering in this code is not secure and can be bypassed by malicious actors. " +
  "It is recommended to use a stack that automatically escapes in your view or templates instead of filtering yourself."