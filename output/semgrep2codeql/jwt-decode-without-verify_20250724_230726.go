/**
 * @name JWT Decode Without Verify
 * @description Detected the decoding of a JWT token without a verify step.
 *              JWT tokens must be verified before use, otherwise the token's
 *              integrity is unknown. This means a malicious actor could forge
 *              a JWT token with any claims. Call '.verify()' before using the token.
 * @kind problem
 * @problem.severity warning
 * @id java/jwt-decode-without-verify
 * @tags security
 *       external/cwe/cwe-345
 *       external/owasp/a08
 *       jwt
 */
import java

from Expr decodeCall
where 
  decodeCall.(MethodAccess).getMethod().hasQualifiedName("com.auth0.jwt", "JWT", "decode")
  and not exists(Expr verifyCall |
    verifyCall.(MethodAccess).getMethod().getName() = "verify"
    and verifyCall.getEnclosingCallable() = decodeCall.getEnclosingCallable()
  )
select decodeCall,
  "JWT token decoded without verification. Use verify() method to ensure token integrity."