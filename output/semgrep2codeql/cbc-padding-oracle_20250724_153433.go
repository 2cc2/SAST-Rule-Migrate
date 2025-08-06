/**
 * @name CBC Padding Oracle Vulnerability
 * @description Using CBC with PKCS5Padding is susceptible to padding oracle attacks.
 *              A malicious actor could discern the difference between plaintext with valid or invalid padding.
 *              Additionally, CBC mode does not include any integrity checks.
 * @kind problem
 * @problem.severity warning
 * @id java/cbc-padding-oracle
 * @tags security
 *       external/cwe/cwe-327
 *       owasp/a03:2017
 *       owasp/a02:2021
 */
import java

from MethodAccess ma
where ma.getMethod().hasName("getInstance") 
  and ma.getQualifier().getType().hasName("Cipher")
  and ma.getAnArgument().(StringLiteral).getValue().matches("%CBC/PKCS5Padding%")
select ma, "Using CBC with PKCS5Padding is vulnerable to padding oracle attacks. Use 'AES/GCM/NoPadding' instead."