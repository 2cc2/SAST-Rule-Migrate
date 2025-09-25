/**
 * @name Insecure Cookie Configuration
 * @description Detects when a cookie is created without setting the secure flag to true,
 *              which could lead to sensitive data exposure over unencrypted connections.
 * @kind problem
 * @problem.severity warning
 * @id java/insecure-cookie-configuration
 * @tags security
 *       external/cwe/cwe-319
 *       external/owasp/a03
 *       external/owasp/a02
 */

import java

class InsecureCookie extends Expr {
  InsecureCookie() {
    exists(Method m |
      m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
      m.getName() = "setSecure" and
      exists(MethodAccess ma |
        ma.getMethod() = m and
        ma.getArgument(0).(BooleanLiteral).getValue() != true and
        this = ma.getQualifier()
      )
    )
    or
    exists(Constructor c |
      c.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
      exists(ConstructorCall cc |
        cc.getConstructor() = c and
        not exists(MethodAccess ma |
          ma.getQualifier() = cc and
          ma.getMethod().getName() = "setSecure" and
          ma.getArgument(0).(BooleanLiteral).getValue() = true
        ) and
        this = cc
      )
    )
  }
}

from InsecureCookie ic
select ic, "Default session middleware settings: `setSecure` not set to true. " +
            "This ensures that the cookie is sent only over HTTPS to prevent cross-site scripting attacks."