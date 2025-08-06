/**
 * @name Weak random number generator
 * @description Detected use of the functions `Math.random()` or `java.util.Random()`.
 * These are both not cryptographically strong random number generators (RNGs).
 * If you are using these RNGs to create passwords or secret tokens,
 * use `java.security.SecureRandom` instead.
 * @kind problem
 * @problem.severity warning
 * @id java/weak-random
 * @tags security
 *       external/cwe/cwe-330
 *       owasp-a2
 */
import java

from 
  MethodAccess mathRandom,
  ClassInstanceExpr randomInstance,
  MethodCall randomMethodCall
where
  (
    mathRandom.getMethod().getName() = "random" and
    mathRandom.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Math")
  )
  or
  (
    exists(randomInstance.getConstructedType()) and
    randomInstance.getConstructedType().hasQualifiedName("java.util", "Random") and
    exists(randomMethodCall.getMethod()) and
    randomMethodCall.getQualifier() = randomInstance
  )
select mathRandom,
"Detected use of weak random number generator. Use java.security.SecureRandom instead for cryptographic purposes."