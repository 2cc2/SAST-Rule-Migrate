/**
 * @name do-privileged-use
 * @description Detects use of AccessController.doPrivileged() and privileged action implementations
 * @kind problem
 * @problem.severity warning
 * @id java/do-privileged-use
 * @tags security
 *   external/cwe/cwe-269
 *   external/owasp/a04
 *   external/certificate/java/dcl54-j
 */

import java

// Matches AccessController.doPrivileged() calls
predicate isDoPrivilegedCall(MethodAccess ma) {
  exists(Method m |
    ma.getMethod() = m and
    m.hasName("doPrivileged") and
    m.getDeclaringType().hasQualifiedName("java.security", "AccessController")
  )
}

// Matches classes implementing PrivilegedAction<Void>
predicate isPrivilegedAction(Class c) {
  exists(InterfaceType it |
    c.getASupertype() = it and
    it.hasQualifiedName("java.security", "PrivilegedAction") and
    it.getSourceDeclaration().getTypeParameters().first().toString() = "Void"
  )
}

from CallSite cs, MethodAccess ma, Class c
where 
  (isDoPrivilegedCall(ma) and cs = ma) or
  (isPrivilegedAction(c) and cs.getEnclosingCallable().getDeclaringType() = c)
select cs, "Marking code as privileged enables a piece of trusted code to temporarily enable access to more resources than are available directly to the code that called it. Be very careful in your use of the privileged construct, and always remember to make the privileged code section as small as possible."