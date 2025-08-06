/**
 * @name Use of insecure SHA1 hash algorithm
 * @description Detected SHA1 hash algorithm which is considered insecure. SHA1 is no
 *              collision resistant and is therefore not suitable as a cryptographic
 *              signature. Instead, use PBKDF2 for password hashing or SHA256/SHA512.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id java/insecure-sha1
 * @tags security
 *       owasp:a3
 *       owasp:a2
 *       cwe:328
 */

import java

from MethodAccess md, Literal algo, MethodAccess sha1
where 
    (
        // Case 1: MessageDigest.getInstance() with SHA1
        md.getMethod().hasName("getInstance") and
        md.getMethod().getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
        algo.getType() instanceof TypeString and
        (algo.getLiteral().matches("%SHA1%") or algo.getLiteral().matches("%SHA-1%")) and
        algo = md.getArgument(0)
    ) or (
        // Case 2: Direct call to getSha1Digest()
        sha1.getMethod().hasName("getSha1Digest")
    )
select md, "Use of insecure SHA1 hash algorithm"