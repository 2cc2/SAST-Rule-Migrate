/**
 * @name Blowfish Insufficient Key Size
 * @description Using less than 128 bits for Blowfish is considered insecure. Use 128 bits or more, or switch to AES instead.
 * @kind problem
 * @id java/blowfish-insufficient-key-size
 * @tags security
 *       external/cwe/cwe-326
 *       owasp/a03:2017
 *       owasp/a02:2021
 *       asvs/v6/6.2.5
 * @precision high
 * @severity warning
 */

import java

from MethodAccess getInstance, MethodAccess keyGenInit, Expr size
where
  getInstance.getMethod().getName() = "getInstance" and
  getInstance.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "KeyGenerator") and
  getInstance.getArgument(0).(StringLiteral).getValue() = "Blowfish" and
  keyGenInit.getMethod().getName() = "init" and
  keyGenInit.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "KeyGenerator") and
  keyGenInit.getQualifier() = getInstance and
  size = keyGenInit.getArgument(0) and
  size instanceof Literal and
  size.(Literal).getValue().toInt() < 128
select keyGenInit, "Using less than 128 bits for Blowfish is considered insecure. Use 128 bits or more, or switch to AES instead."