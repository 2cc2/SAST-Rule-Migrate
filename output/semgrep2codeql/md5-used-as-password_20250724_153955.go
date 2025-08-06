/**
 * @name MD5 used as password hash
 * @description Detects when MD5 is used as a password hash. MD5 is not considered secure
 *              for password hashing. Use PBKDF2 or bcrypt instead.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @tags security
 *       java
 *       md5
 *       owasp-a3
 *       owasp-a2
 *       cwe-327
 * @id java/md5-password-hash
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.frameworks.spring.SpringController

class MD5Usage extends DataFlow::Configuration {
  MD5Usage() { 
    this = "MD5 password usage" 
  }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m, MethodCall mc |
      m.hasName("getInstance") and
      m.getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
      mc.getMethod() = m and
      mc.getArgument(0).(StringLiteral).getValue().toUpperCase() = "MD5" and
      source.asExpr() = mc
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Method m, MethodCall mc, RefType model |
      m.getName().matches("%password%") and
      mc.getMethod() = m and
      mc.getQualifier().getType() = model and
      sink.asExpr() = mc.getAnArgument()
    )
  }
}

from MD5Usage config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Using MD5 for password hashing is insecure. Use PBKDF2 or bcrypt instead."