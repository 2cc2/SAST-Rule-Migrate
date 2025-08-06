/**
 * @name Static Initialization Vector
 * @description Initialization Vectors (IVs) for block ciphers should be randomly generated each time they are used.
 *              Using a static IV means the same plaintext encrypts to the same ciphertext every time,
 *              weakening the strength of the encryption.
 * @kind path-problem
 * @problem.severity warning
 * @id java/static-initialization-vector
 * @tags security
 *       external/cwe/cwe-329
 *       external/owasp/a02
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class StaticIV extends DataFlow::Node {
  StaticIV() {
    exists(ArrayCreationExpr ace |
      this.asExpr() = ace and
      (
        // Case 1: Local variable declaration
        exists(Variable v |
          v.getInitializer() = ace and
          v.getType().toString() = "byte[]"
        )
        or
        // Case 2: Field declaration
        exists(Field f |
          f.getInitializer() = ace and
          f.getType().toString() = "byte[]"
        )
      )
    )
  }
}

class IvParameterSpecCreation extends DataFlow::Node {
  IvParameterSpecCreation() {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("javax.crypto.spec", "IvParameterSpec") and
      this.asExpr() = cc.getArgument(0)
    )
  }
}

class StaticIVConfig extends TaintTracking::Configuration {
  StaticIVConfig() { this = "StaticIV" }

  override predicate isSource(DataFlow::Node source) { source instanceof StaticIV }

  override predicate isSink(DataFlow::Node sink) { sink instanceof IvParameterSpecCreation }

  override predicate isSanitizer(DataFlow::Node sanitizer) { none() }
}

from StaticIVConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Static Initialization Vector (IV) detected, IVs should be randomly generated each time"