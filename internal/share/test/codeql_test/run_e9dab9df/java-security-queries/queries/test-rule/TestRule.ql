/**
 * @name do-privileged-use
 * @description Marking code as privileged enables a piece of trusted code to temporarily
 * enable access to more resources than are available directly to the code
 * that called it. Be very careful in your use of the privileged construct,
 * and always remember to make the privileged code section as small as possible.
 * @kind problem
 * @id java/do-privileged-use
 * @severity Warning
 * @tags security
 *       external/cwe/cwe-269
 *       owasp/a04
 */
import java

from MethodAccess ma, Method m
where 
  (m.hasQualifiedName("java.security", "AccessController", "doPrivileged") and
   ma.getMethod() = m)
  or
  exists(Class c |
    c.getASupertype*().hasQualifiedName("java.security", "PrivilegedAction") and
    ma.getEnclosingCallable().getDeclaringType() = c
  )
select ma, "Use of privileged code construct detected. This enables privilege escalation and should be minimized and carefully reviewed."