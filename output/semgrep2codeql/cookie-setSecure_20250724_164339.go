/**
 * @name Insecure Cookie setSecure Configuration
 * @description Detects when a Cookie's setSecure method is set to false without ever being set to true.
 * @kind path-problem
 * @problem.severity warning
 * @id java/cookie-setSecure
 * @tags security
 *       owasp/a03:2017
 *       owasp/a02:2021
 *       cwe/319
 */

import java

predicate isCookieConstructorCall(Expr call) {
  call instanceof ConstructorCall and
  exists(Constructor c | call.(ConstructorCall).getConstructor() = c and 
    c.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie"))
}

predicate isSetSecureCall(MethodAccess setSecureCall, Expr cookieVar) {
  exists(Method m | 
    setSecureCall.getMethod() = m and
    m.hasName("setSecure") and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
    setSecureCall.getQualifier() = cookieVar
  )
}

from
  ConstructorCall cookieConstructor, LocalVariableDecl cookieVar,
  MethodAccess insecureSetSecureCall
where
  isCookieConstructorCall(cookieConstructor) and
  cookieVar.getAnAssignedValue() = cookieConstructor and
  isSetSecureCall(insecureSetSecureCall, cookieVar.getAnAccess()) and
  insecureSetSecureCall.getArgument(0) instanceof Literal and
  insecureSetSecureCall.getArgument(0).(Literal).getValue().toInt() = 0 and
  not exists(MethodAccess secureSetSecureCall |
    isSetSecureCall(secureSetSecureCall, cookieVar.getAnAccess()) and
    secureSetSecureCall.getArgument(0) instanceof Literal and
    secureSetSecureCall.getArgument(0).(Literal).getValue().toInt() = 1 and
    secureSetSecureCall.getEnclosingStmt().getLocation().getStartLine() >
      insecureSetSecureCall.getEnclosingStmt().getLocation().getStartLine()
  )
select insecureSetSecureCall,
  "Default session middleware settings: `setSecure` not set to true. This ensures that the cookie is sent only over HTTPS to prevent cross-site scripting attacks.",
  insecureSetSecureCall,
  "Consider setting setSecure(true) for security"