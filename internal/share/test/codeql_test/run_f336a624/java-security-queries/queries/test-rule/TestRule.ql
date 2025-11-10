/**
 * @name NullCipher Usage
 * @description Detects usage of NullCipher which provides no encryption.
 * @kind problem
 * @problem.severity warning
 * @id java/no-null-cipher
 * @tags security
 *       external/cwe/cwe-327
 *       owasp/a03:2017
 *       owasp/a02:2021
 */

import java

from ConstructorCall c
where c.getConstructedType().hasQualifiedName("javax.crypto", "NullCipher") or
      c.getConstructedType().hasQualifiedName("", "NullCipher")
select c, "NullCipher was detected. This will not encrypt anything; the cipher text will be the same as the plain text. " +
          "Use a valid, secure cipher: Cipher.getInstance(\"AES/CBC/PKCS7PADDING\"). " +
          "See https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions for more information."