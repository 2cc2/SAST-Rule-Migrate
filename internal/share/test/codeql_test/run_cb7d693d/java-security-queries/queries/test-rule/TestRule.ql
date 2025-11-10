/**
 * @name Use of Blowfish
 * @description Blowfish uses a 64-bit block size that makes it vulnerable to birthday attacks.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id java/use-of-blowfish
 * @tags security
 *       cwe/327
 *       owasp/a03
 *       owasp/a02
 *       external/cwe/cwe-327
 */
import java

from MethodAccess ma
where ma.getMethod().hasName("getInstance") 
  and ma.getArgument(0).toString() = "\"Blowfish\""
select ma, 
  "Use of Blowfish was detected. Blowfish uses a 64-bit block size that makes it vulnerable to birthday attacks, and is therefore considered non-compliant. Instead, use a strong, secure cipher: Cipher.getInstance(\"AES/CBC/PKCS7PADDING\"). See https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions for more information."