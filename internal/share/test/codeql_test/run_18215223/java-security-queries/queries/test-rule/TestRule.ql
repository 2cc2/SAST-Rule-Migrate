/**
 * @name Avoid implementing custom digests
 * @description Cryptographic algorithms are notoriously difficult to get right. By implementing
 * a custom message digest, you risk introducing security issues into your program.
 * Use one of the many sound message digests already available to you:
 * MessageDigest sha256Digest = MessageDigest.getInstance("SHA256");
 * @kind problem
 * @problem.severity warning
 * @id java/avoid-implementing-custom-digests
 * @tags security
 *   - external/cwe/cwe-327
 *   - external/owasp/a03:2017
 *   - external/owasp/a02:2021
 */
import java

from RefType r
where r.getASupertype().getQualifiedName() = "java.security.MessageDigest"
select r, "Avoid implementing custom message digests. Use standard cryptographic algorithms instead."