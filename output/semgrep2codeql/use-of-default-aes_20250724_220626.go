/**
 * @name Use of default AES encryption
 * @description Detects usage of AES without specifying mode and padding (defaults to ECB mode which is insecure)
 * @kind path-problem
 * @problem.severity warning
 * @id java/use-of-default-aes
 * @tags security
 *       external/cwe/cwe-327
 *       owasp-a3:2017
 *       owasp-a2:2021
 */

import java
import semmle.code.java.dataflow.FlowSources

class DefaultAESCall extends MethodAccess {
  DefaultAESCall() {
    exists(Method m |
      m = this.getMethod() and
      m.hasName("getInstance") and
      m.getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
      this.getArgument(0).toString() = "\"AES\""
    )
  }
}

from DefaultAESCall call
select call, "Use of AES with no settings detected. By default, java.crypto.Cipher uses ECB mode. " +
  "ECB doesn't provide message confidentiality and is not semantically secure so should not be used. " +
  "Instead, use a strong, secure cipher: java.crypto.Cipher.getInstance(\"AES/CBC/PKCS7PADDING\"). " +
  "See https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions"