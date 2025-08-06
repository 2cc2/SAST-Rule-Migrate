/**
 * @name Cookie Missing HttpOnly Flag
 * @description Detects cookies that don't have the HttpOnly flag set.
 * @kind problem
 * @problem.severity warning
 * @id java/cookie-missing-httponly
 * @tags security
 *       external/cwe/cwe-1004
 *       owasp/a05:2021
 */

import java

from MethodAccess setHttpOnlyCall, MethodAccess addCookieCall,
     MethodAccess cookieCreation
where 
  (
    addCookieCall.getMethod().hasName("addCookie") and
    not exists(
      MethodAccess ma |
      ma.getMethod().hasName("setHttpOnly") and
      ma.getQualifier() = addCookieCall.getArgument(0)
    )
  )
  or
  (
    setHttpOnlyCall.getMethod().hasName("setHttpOnly") and
    exists(BooleanLiteral bl |
      bl = setHttpOnlyCall.getArgument(0) and
      bl.getBooleanValue() = false
    )
  )
  or
  (
    cookieCreation.getMethod().hasName("from") and
    not exists(MethodAccess ma |
      ma.getQualifier() = cookieCreation and
      ma.getMethod().hasName("httpOnly")
    )
  )
select addCookieCall, "A cookie was detected without setting the 'HttpOnly' flag. " +
       "The 'HttpOnly' flag for cookies instructs the browser to forbid client-side " +
       "scripts from reading the cookie. Set the 'HttpOnly' flag by calling " +
       "'cookie.setHttpOnly(true);'"