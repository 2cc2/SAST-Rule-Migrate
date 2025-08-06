/**
 * @name Weak SSL Context
 * @description Detects insecure SSL contexts using deprecated protocols (TLS 1.0/1.1 or SSL)
 * @kind problem
 * @problem.severity warning
 * @id java/weak-ssl-context
 * @tags security
 *       weakness/cwe-326
 *       owasp/a03:2017
 *       owasp/a02:2021
 */

import java

from MethodCall ma
where 
  ma.getMethod().hasName("getInstance") and
  ma.getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLContext") and
  not ma.getArgument(0).(StringLiteral).getValue().matches("^TLSv1\\.3$") and
  not ma.getArgument(0).(StringLiteral).getValue().matches("^TLSv1\\.2$")
select ma, "An insecure SSL context was detected. TLS versions 1.0, 1.1, and all SSL versions are considered weak encryption and are deprecated. Use SSLContext.getInstance(\"TLSv1.2\") for the best security."