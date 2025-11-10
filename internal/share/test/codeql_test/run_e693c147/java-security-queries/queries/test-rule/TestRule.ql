/**
 * @name JWT None Algorithm
 * @description Detected use of the 'none' algorithm in a JWT token.
 * @kind problem
 * @problem.severity error
 * @id java/jjwt-none-alg
 * @tags security
 *       cwe/327
 *       owasp/a03
 *       owasp/a02
 *       jwt
 */

import java

from MethodCall builder
where 
  builder.getMethod().hasName("builder") and
  builder.getMethod().getDeclaringType().hasQualifiedName("io.jsonwebtoken", "Jwts") and
  not exists(
    MethodCall signWith |
    signWith.getMethod().hasName("signWith") and
    signWith.getEnclosingCallable() = builder.getEnclosingCallable()
  )
select builder, "Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'."