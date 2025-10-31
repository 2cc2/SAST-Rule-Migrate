/**
 * @name XSSRequestWrapper is insecure
 * @description Detects usage of insecure XSSRequestWrapper implementation
 * @kind problem
 * @id java/xssrequestwrapper-is-insecure
 * @security-severity 8.8
 * @tags security
 *       external/cwe/cwe-79
 *       owasp-a7
 *       owasp-a3
 */

import java

from Class cls, Method method, MethodAccess call
where
  // Source: XSS_REQUEST_WRAPPER
  cls.getName() = "XSSRequestWrapper" and
  cls.getASupertype() instanceof TypeHttpServletRequestWrapper and
  
  // Source: INSECURE_SCRIPT_FILTER
  (
    call.getMethod().getName() = "compile" and
    call.getMethod().getDeclaringType().getName() = "Pattern" and
    exists(call.getArgument(0) | 
      this.getStringValue() = "</script>"
    )
  )
select method, "It looks like you're using an implementation of XSSRequestWrapper "
  + "from dzone. (https://www.javacodegeeks.com/2012/07/anti-cross-site-scripting-xss-filter.html) "
  + "The XSS filtering in this code is not secure and can be bypassed by malicious actors. "
  + "It is recommended to use a stack that automatically escapes in your view or "
  + "templates instead of filtering yourself."