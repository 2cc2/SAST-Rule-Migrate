/**
 * @name Insecure Cookie Configuration
 * @description Detects when a Cookie is created without setting the secure flag,
 *              which can lead to sensitive data transmission over unencrypted channels.
 * @kind problem
 * @problem.severity warning
 * @id java/cookie-issecure-false
 * @tags security
 *       owasp/a03:2017
 *       owasp/a02:2021
 *       cwe/319
 */
import java

from ConstructorCall cookieCtor
where
  cookieCtor.getConstructedType().hasQualifiedName("javax.servlet.http", "Cookie") and
  not exists(
    MethodAccess setSecureCall |
    setSecureCall.getMethod().hasName("setSecure") and
    setSecureCall.getQualifier() = cookieCtor
  )
select cookieCtor, "Cookie created without secure flag. Ensure to call setSecure(true) to prevent transmission over unencrypted channels."