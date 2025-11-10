/**
 * @name URL rewriting
 * @description URL rewriting has significant security risks.
 *              Since session ID appears in the URL, it may be easily seen by third parties.
 * @kind problem
 * @problem.severity warning
 * @id java/url-rewriting
 * @tags security
 *       external/cwe/cwe-200
 *       external/owasp/a01
 */
import java

from MethodAccess ma, Method m
where 
  (ma.getMethod().hasName("encodeURL") or
   ma.getMethod().hasName("encodeUrl") or
   ma.getMethod().hasName("encodeRedirectURL") or
   ma.getMethod().hasName("encodeRedirectUrl")) and
  ma.getQualifier().getType().hasName("HttpServletResponse") and
  m = ma.getEnclosingCallable()
select ma, "URL rewriting has security risks as it exposes session IDs in URLs."