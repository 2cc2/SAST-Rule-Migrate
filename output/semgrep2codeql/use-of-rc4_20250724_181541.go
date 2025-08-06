/**
 * @name Use of RC4
 * @description Detects usage of RC4 cipher which is vulnerable to several attacks including stream cipher attacks and bit flipping attacks.
 * @kind problem
 * @problem.severity warning
 * @id java/use-of-rc4
 * @tags security
 *       external/cwe/cwe-327
 *       external/owasp/a03:2017
 *       external/owasp/a02:2021
 */
import java

from MethodAccess ma
where 
  ma.getMethod().getName() = "getInstance" and
  ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
  ma.getArgument(0).(StringLiteral).getValue() = "RC4"
select ma, "Use of RC4 was detected. RC4 is vulnerable to several attacks, including " +
  "stream cipher attacks and bit flipping attacks. Instead, use a strong, secure " +
  "cipher: Cipher.getInstance(\"AES/CBC/PKCS7PADDING\"). " +
  "See https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions " +
  "for more information."