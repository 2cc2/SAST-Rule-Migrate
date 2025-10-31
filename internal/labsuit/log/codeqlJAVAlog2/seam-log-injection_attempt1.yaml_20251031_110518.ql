/**
 * @name Seam Log Injection
 * @description Detects potential expression language injection in Seam logging API calls.
 * @kind path-problem
 * @problem.severity ERROR
 * @precision high
 * @id java/seam-log-injection
 * @tags security
 *       jboss
 *       external/cwe/cwe-095
 *       owasp-a03
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.JBossSeam

class SeamLogCall extends MethodAccess {
  SeamLogCall() {
    exists(Method m | 
      m = this.getMethod() and
      m.getDeclaringType().hasQualifiedName("org.jboss.seam.log", "Log") and
      (m.getName().matches("debug") or 
       m.getName().matches("error") or
       m.getName().matches("fatal") or
       m.getName().matches("info") or
       m.getName().matches("trace") or
       m.getName().matches("warn"))
    )
  }
}

class LogSource extends DataFlow::Node {
  LogSource() {
    exists(SeamLogCall call | this.asExpr() = call)
  }
}

class LogSink extends DataFlow::Node {
  LogSink() {
    exists(SeamLogCall call | call.getArgument(0) = this.asExpr())
  }
}

class SeamLogInjectionConfig extends TaintTracking::Configuration {
  SeamLogInjectionConfig() { this = "SeamLogInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof LogSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof LogSink
  }

  override predicate isExtension(DataFlow::Node node1, DataFlow::Node node2) {
    TaintTracking::localTaintStep(node1, node2)
  }
}

from SeamLogInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, 
  "Seam Logging API supports expression language that can lead to code injection when using dynamic values",
  source, sink,
  "The logging method uses potentially unsafe input which may allow EL injection."