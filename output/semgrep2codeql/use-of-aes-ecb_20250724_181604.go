/**
 * @name Use of AES ECB mode
 * @description Detects usage of AES with ECB mode which doesn't provide message confidentiality.
 * @kind problem
 * @problem.severity warning
 * @id java/use-of-aes-ecb
 * @tags security
 *       external/cwe/cwe-327
 *       owasp/a03:2017
 *       owasp/a02:2021
 * @precision high
 */
import java

from MethodAccess ma
where
  ma.getMethod().hasName("getInstance") and
  ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
  exists(Expr arg | arg = ma.getArgument(0) |
    arg instanceof StringLiteral and
    arg.toString().regexpMatch("AES/ECB.*")
  )
select ma, "Use of AES with ECB mode detected. ECB doesn't provide message confidentiality and " +
  "is not semantically secure so should not be used. Instead, use a strong, secure cipher: " +
  "Cipher.getInstance(\"AES/CBC/PKCS7PADDING\"). See " +
  "https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions for more information."