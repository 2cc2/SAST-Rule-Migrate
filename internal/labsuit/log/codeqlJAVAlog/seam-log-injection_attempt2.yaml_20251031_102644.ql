/**
 * @name Seam Log Injection
 * @description Detects log injection vulnerabilities in JBoss Seam Framework
 * @id seam-log-injection
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @tags security
 *       external/cwe/cwe-095
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class SeamLogSource extends DataFlow::ExprNode {
  SeamLogSource() {
    exists(Method m | 
      m.getDeclaringType().hasQualifiedName("org.jboss.seam.log", "Log") and
      m.getName().matches("debug|error|fatal|info|trace|warn") and
      this = m.getACall()
    )
  }
}

class SeamLogSink extends DataFlow::ExprNode {
  SeamLogSink() {
    exists(Method m | 
      m.getDeclaringType().hasQualifiedName("org.jboss.seam.log", "Log") and
      m.getName().matches("debug|error|fatal|info|trace|warn") and
      this = m.getACall()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SeamLogSink logCall |
      sink.asExpr() = logCall and
      sink = logCall.getArgument(0)
    )
  }
}

class SeamLogConfig extends TaintTracking::Configuration {
  SeamLogConfig() { this = "SeamLogConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SeamLogSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SeamLogSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node src, DataFlow::Node sink) {
    exists(DataFlow::ParameterNode param, DataFlow::ArgumentNode arg |
      arg = src.asParameter() and
      param = sink.asArgument() and
      param.(DataFlow::ParameterNode).getCall() = arg.(DataFlow::ArgumentNode).getCall()
    )
  }
}

from SeamLogConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, 
  source, sink,
  "Potential log injection vulnerability in JBoss Seam. Unsanitized input flows to log expression."