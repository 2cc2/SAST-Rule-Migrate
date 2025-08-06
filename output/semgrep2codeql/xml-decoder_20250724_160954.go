/**
 * @name Unsafe XMLDecoder usage
 * @description Detects usage of XMLDecoder with untrusted data which could lead to arbitrary code execution.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.0
 * @precision high
 * @id java/unsafe-xmldecoder
 * @tags security
 *       external/cwe/cwe-611
 *       owasp-a04:2017
 *       owasp-a05:2021
 */
import java
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

class XMLDecoderConstructorCall extends ConstructorCall {
  XMLDecoderConstructorCall() {
    this.getConstructedType().hasQualifiedName("java.beans", "XMLDecoder")
  }
  
  override Constructor getConstructor() {
    result.getDeclaringType().hasQualifiedName("java.beans", "XMLDecoder")
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "UnsafeXMLDecoderConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(ConstructorCall cc |
      cc instanceof XMLDecoderConstructorCall and
      sink.asExpr() = cc.getArgument(0)
    )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential unsafe XMLDecoder usage with untrusted data. This can lead to arbitrary code execution."