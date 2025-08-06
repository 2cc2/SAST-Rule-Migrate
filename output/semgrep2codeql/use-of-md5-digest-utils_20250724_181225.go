/**
 * @name Use of MD5 DigestUtils
 * @description Detected MD5 hash algorithm which is considered insecure. MD5 is not
 *              collision resistant and is therefore not suitable as a cryptographic
 *              signature. Use HMAC instead.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id java/use-of-md5-digest-utils
 * @tags security
 *       external/cwe/cwe-328
 *       owasp-a02:2021
 *       owasp-a03:2017
 */

import java

predicate isMd5DigestUtilsCall(Expr expr) {
  expr instanceof MethodAccess and
  exists(Method m |
    expr.(MethodAccess).getMethod() = m and
    m.hasName("getMd5Digest") and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "DigestUtils")
  )
}

from Expr md5Call
where isMd5DigestUtilsCall(md5Call)
select md5Call, "Use of MD5 hash algorithm which is considered insecure. Use SHA-512 or HMAC instead."