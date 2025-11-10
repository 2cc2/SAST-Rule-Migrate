/**
 * @name Use of SHA224
 * @description This code uses a 224-bit hash function, which is deprecated or disallowed
 *    in some security policies. Consider updating to a stronger hash function such
 *    as SHA-384 or higher to ensure compliance and security.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id java/use-of-sha224
 * @tags security
 *       external/cwe/cwe-328
 *       external/owasp/a03:2017
 *       external/owasp/a02:2021
 *       external/asvs/6.2.5
 */
import java

from MethodAccess ma, Method m, ClassInstanceExpr cie, Constructor c, StringLiteral algo
where
  // Pattern 1: DigestUtils methods
  (
    m.hasName(["getSha3_224Digest", "getSha512_224Digest", "sha3_224", "sha3_224Hex", 
              "sha512_224", "sha512_224Hex"]) and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "DigestUtils") and
    ma.getMethod() = m
  )
  or
  // Pattern 2: DigestUtils constructors with weak algorithms
  (
    c.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "DigestUtils") and
    (
      algo.getValue() = "SHA_224" or
      algo.getValue() = "SHA_512_224" or
      algo.getValue() = "SHA3_224"
    ) and
    cie.getConstructor() = c and
    algo = cie.getAnArgument()
  )
  or
  // Pattern 3: MessageDigest.getInstance with weak algorithms
  (
    m.hasName("getInstance") and
    m.getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
    ma.getMethod() = m and
    algo.getValue().regexpMatch(".*224") and
    algo = ma.getArgument(0)
  )
select ma, "Use of weak 224-bit hash function detected"