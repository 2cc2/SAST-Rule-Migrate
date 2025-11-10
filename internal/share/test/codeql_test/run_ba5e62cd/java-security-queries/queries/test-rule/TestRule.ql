/**
 * @name GCM Nonce Reuse
 * @description Detects reuse of GCM IV/nonce which can make encryption useless
 * @kind path-problem
 * @problem.severity error
 * @id java/gcm-nonce-reuse
 * @tags security
 *       external/cwe/cwe-323
 *       external/owasp/a02
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class GCMConstructor extends DataFlow::Node {
  GCMConstructor() {
    exists(Call ma |
      ma.getCallee().getName() = "GCMParameterSpec" and
      this.asExpr() = ma
    )
  }
}

class StringGetBytes extends DataFlow::Node {
  StringGetBytes() {
    exists(Call ma |
      ma.getCallee().getName() = "getBytes" and
      ma.getQualifier() instanceof StringLiteral and
      this.asExpr() = ma
    )
  }
}

class NonceReuseConfig extends TaintTracking::Configuration {
  NonceReuseConfig() { this = "NonceReuseConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringGetBytes
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof GCMConstructor
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) { none() }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, NonceReuseConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "GCM IV/nonce is reused: encryption can be totally useless"