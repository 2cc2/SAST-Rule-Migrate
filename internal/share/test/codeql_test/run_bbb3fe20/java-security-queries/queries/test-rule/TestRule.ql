/**
 * @name Use of RC2 Cipher
 * @description Detects usage of RC2 cipher which is vulnerable to related-key attacks.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id java/use-of-rc2
 * @tags security
 *       external/cwe/cwe-327
 *       owasp-a03:2017
 *       owasp-a02:2021
 */

import java

from MethodAccess ma
where ma.getMethod().hasName("getInstance")
  and ma.getArgument(0).(StringLiteral).getValue() = "RC2"
select ma, "Use of RC2 was detected. RC2 is vulnerable to related-key attacks, and is therefore considered non-compliant. Instead, use a strong, secure cipher: Cipher.getInstance(\"AES/CBC/PKCS7PADDING\"). See https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions for more information."