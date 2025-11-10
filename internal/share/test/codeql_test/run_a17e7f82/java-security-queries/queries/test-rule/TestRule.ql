/**
 * @name Desede is deprecated
 * @description Triple DES (3DES or DESede) is considered deprecated. AES is the recommended cipher.
 * @kind problem
 * @problem.severity warning
 * @id java/desede-is-deprecated
 * @tags security
 *       external/cwe/cwe-326
 *       external/owasp/a03:2017
 *       external/owasp/a02:2021
 *       crypto::search::symmetric-algorithm::javax.crypto
 */
import java

from MethodAccess ma, Literal l
where 
  (
    ma.getMethod().hasName("getInstance") and
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    l = ma.getArgument(0) and
    l.getType() instanceof TypeString and
    l.getValue().matches("DESede.*")
  )
  or
  (
    ma.getMethod().hasName("getInstance") and
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "KeyGenerator") and
    l = ma.getArgument(0) and
    l.getType() instanceof TypeString and
    l.getValue().matches("DES")
  )
select ma, "Triple DES (3DES or DESede) is deprecated. Use AES instead."