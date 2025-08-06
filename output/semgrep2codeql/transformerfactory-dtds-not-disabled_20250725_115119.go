/**
 * @name TransformerFactory DTDs Not Disabled
 * @description DOCTYPE declarations are enabled for TransformerFactory instances, making them
 *              vulnerable to XML external entity attacks.
 * @kind path-problem
 * @problem.severity error
 * @id java/transformerfactory-dtds-not-disabled
 * @tags security
 *       external/cwe/cwe-611
 *       external/owasp/a04
 *       external/owasp/a05
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class TransformerFactorySource extends DataFlow::ExprNode {
  TransformerFactorySource() {
    exists(Call ma |
      ma.getCallee().getName() = "newInstance" and
      ma.getCallee().getDeclaringType().hasQualifiedName("javax.xml.transform", "TransformerFactory") and
      this.asExpr() = ma
    )
  }
}

class TransformerFactorySink extends DataFlow::ExprNode {
  TransformerFactorySink() {
    exists(Call ma |
      ma.getCallee().getName() = "newTransformer" and
      this.asExpr() = ma.getQualifier()
    )
  }
}

class SecureAttributes extends DataFlow::Node {
  SecureAttributes() {
    exists(Call ma |
      (ma.getCallee().getName() = "setAttribute" and
       (ma.getArgument(0).(FieldAccess).getField().getName() = "ACCESS_EXTERNAL_DTD" or
        ma.getArgument(0).toString().matches("%accessExternalDTD%") or
        ma.getArgument(0).(FieldAccess).getField().getName() = "ACCESS_EXTERNAL_STYLESHEET" or
        ma.getArgument(0).toString().matches("%accessExternalStylesheet%")) and
       ma.getArgument(1).(StringLiteral).getValue() = "") and
      this.asExpr() = ma.getQualifier()
    )
  }
}

class TransformerFactoryConfig extends TaintTracking::Configuration {
  TransformerFactoryConfig() { this = "TransformerFactoryConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof TransformerFactorySource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof TransformerFactorySink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(SecureAttributes sa |
      node.asExpr() = sa.asExpr()
    )
  }
}

from TransformerFactoryConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "DOCTYPE declarations are enabled for this TransformerFactory. This is vulnerable to XML external entity attacks. Disable this by setting the attributes 'accessExternalDTD' and 'accessExternalStylesheet' to empty string."