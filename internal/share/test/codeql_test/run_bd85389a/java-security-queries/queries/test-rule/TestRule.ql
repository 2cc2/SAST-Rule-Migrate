/**
 * @name Use of Weak RSA Key
 * @description RSA keys should be at least 2048 bits based on NIST recommendation.
 * @kind path-problem
 * @problem.severity warning
 * @id java/use-of-weak-rsa-key
 * @tags security
 *       external/cwe/cwe-326
 *       external/owasp/a03
 *       external/owasp/a02
 */

import java
import semmle.code.java.dataflow.TaintTracking

class KeyPairGenerator extends RefType {
  KeyPairGenerator() { 
    this.getQualifiedName() = "java.security.KeyPairGenerator"
  }
}

class KeyPairGeneratorCall extends DataFlow::Node {
  KeyPairGeneratorCall() {
    exists(Call ma |
      ma.getCallee().getName() = "getInstance" and
      ma.getCallee().getDeclaringType() instanceof KeyPairGenerator and
      ma.getArgument(0).(StringLiteral).getValue() = "RSA" and
      this.asExpr() = ma
    )
  }
}

class InitializeCall extends DataFlow::Node {
  InitializeCall() {
    exists(Call ma |
      ma.getCallee().getName() = "initialize" and
      ma.getCallee().getDeclaringType() instanceof KeyPairGenerator and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class WeakRSAKeyConfig extends TaintTracking::Configuration {
  WeakRSAKeyConfig() { this = "WeakRSAKeyConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof KeyPairGeneratorCall
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Literal keySize |
      sink.asExpr() = keySize and
      keySize.getValue().toInt() < 2048 and
      exists(InitializeCall init | sink = init)
    )
  }
}

from WeakRSAKeyConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "RSA keys should be at least 2048 bits based on NIST recommendation.",
  source, sink, "Weak RSA key size used"