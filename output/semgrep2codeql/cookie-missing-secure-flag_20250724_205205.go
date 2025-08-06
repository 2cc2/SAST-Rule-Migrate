/**
 * @name Cookie Missing Secure Flag
 * @description Detects cookies created without the secure flag set.
 * @kind path-problem
 * @problem.severity warning
 * @id java/cookie-missing-secure-flag
 * @tags security
 *       external/cwe/cwe-614
 *       external/owasp/a05
 */
import java

from MethodAccess setSecureCall, MethodAccess addCookieCall, 
     Expr cookieExpr, Expr responseExpr
where
  // Find calls to setSecure(false)
  (
    setSecureCall.getMethod().hasName("setSecure") and
    setSecureCall.getArgument(0).(BooleanLiteral).getValue() = "false" and
    cookieExpr = setSecureCall.getQualifier()
  )
  or
  // Find addCookie calls where setSecure is not called before
  (
    addCookieCall.getMethod().hasName("addCookie") and
    responseExpr = addCookieCall.getQualifier() and
    cookieExpr = addCookieCall.getArgument(0) and
    not exists(MethodAccess safeSetSecure | 
      safeSetSecure.getMethod().hasName("setSecure") and
      safeSetSecure.getQualifier() = cookieExpr and
      safeSetSecure.getArgument(0).(BooleanLiteral).getValue() = "true"
    ) and
    not exists(MethodAccess responseCookieCreate |
      responseCookieCreate.getMethod().getName().matches("from%") and
      responseCookieCreate.getQualifier().getType().(RefType).hasQualifiedName("org.springframework.http", "ResponseCookie")
    )
  )
select addCookieCall, 
  "A cookie was detected without setting the 'secure' flag. The 'secure' flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP.", 
  addCookieCall.getLocation(),
  "Set the 'secure' flag by calling '$COOKIE.setSecure(true);'",
  "cookie-missing-secure-flag"