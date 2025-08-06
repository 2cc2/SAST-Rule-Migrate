/**
 * @name Bad Hexadecimal Conversion
 * @description Detects usage of Integer.toHexString() that strips leading zeroes,
 *              which can weaken hash values by introducing more collisions.
 * @kind problem
 * @problem.severity warning
 * @id java/bad-hexa-conversion
 * @tags security
 *       external/cwe/cwe-704
 *       owasp-a3
 */

import java

from MethodAccess ma, Method md, MethodCall mc
where
  // Find calls to MessageDigest.digest()
  md.hasName("digest") and
  md.getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
  mc.getMethod() = md and
  // Find calls to Integer.toHexString() in the same method
  ma.getMethod().hasName("toHexString") and
  ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Integer") and
  ma.getEnclosingCallable() = mc.getEnclosingCallable()
select ma, "Use String.format(\"%02X\", ...) instead of Integer.toHexString() to preserve leading zeroes in hash computations."