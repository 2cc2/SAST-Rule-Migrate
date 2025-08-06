/**
 * @name DES is deprecated
 * @description DES is considered deprecated. AES is the recommended cipher.
 * @kind problem
 * @problem.severity warning
 * @id java/des-deprecated
 * @tags security
 *       external/cwe/cwe-326
 *       owasp/a03:2017
 *       owasp/a02:2021
 *       technology/java
 */

import java

from MethodCall ma, StringLiteral le
where
  (
    ma.getMethod().hasName("getInstance") and
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    (
      le.getValue().regexpMatch("(?i)DES.*") or
      le.getValue() = "DES"
    ) and
    ma.getArgument(0) = le
  )
select ma, "DES is considered deprecated. Use AES instead. See " +
  "https://www.nist.gov/news-events/news/2005/06/nist-withdraws-outdated-data-encryption-standard"