/**
 * @name ECB Cipher Detection
 * @description Detects usage of Cipher in ECB mode which is insecure
 * @kind problem
 * @id java/ecb-cipher
 * @tags security
 *       external/cwe/cwe-327
 *       owasp/a03:2017
 *       owasp/a02:2021
 * @problem.severity warning
 */

import java

from MethodCall cipherGetInstance, StringLiteral mode
where 
  cipherGetInstance.getMethod().hasName("getInstance") and
  cipherGetInstance.getQualifier().getType().hasName("Cipher") and
  mode = cipherGetInstance.getArgument(0) and
  mode.getValue().matches("%ECB%")
select cipherGetInstance, 
  "Cipher in ECB mode is detected. ECB mode produces the same output for the same input each time " +
  "which allows an attacker to intercept and replay the data. Further, ECB mode does not provide " +
  "any integrity checking. See https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY."