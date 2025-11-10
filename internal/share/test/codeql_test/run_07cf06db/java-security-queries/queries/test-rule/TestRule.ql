/**
 * @name RSA No Padding
 * @description Using RSA without OAEP mode weakens the encryption.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id java/rsa-no-padding
 * @tags security
 *       weakness
 *       cwe/326
 *       owasp/a03:2017
 *       owasp/a02:2021
 */

import java

from MethodAccess ma, Literal l
where ma.getMethod().hasName("getInstance") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
      l.getType() instanceof TypeString and
      l.toString().matches("%RSA/[Nn][Oo][Nn][Ee]/NoPadding%")
select ma, "Using RSA without OAEP mode weakens the encryption."