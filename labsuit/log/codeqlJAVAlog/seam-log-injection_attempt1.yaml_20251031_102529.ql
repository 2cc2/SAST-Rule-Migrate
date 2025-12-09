/**
 * @name Seam Log Injection
 * @kind problem
 * @id java/seam-log-injection
 * @severity ERROR
 * @description >
 *  Seam Logging API support an expression language to introduce bean property to log messages.
 *  The expression language can also be the source to unwanted code execution.
 *  In this context, an expression is built with a dynamic value.
 *  The source of the value(s) should be verified to avoid that unfiltered values fall into this risky
 *  code evaluation.
 * @tags jboss
 * @security-severity 8.8
 * @precision high
 * @kind path-problem
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class SeamLogSource extends DataFlow::CallNode {
  SeamLogSource() {
    this.getTarget().hasQualifiedName("org.jboss.seam.log", "Log") and
    this.getTarget().getName().matches(["debug", "error", "fatal", "info", "trace", "warn"])
  }
}

class SeamLogSink extends DataFlow::CallNode {
  SeamLogSink() {
    this.getTarget().hasQualifiedName("org.jboss.seam.log", "Log") and
    this.getTarget().getName().matches(["debug", "error", "fatal", "info", "trace", "warn"]) and
    this.getArgument(0) = any(DataFlow::Node source)
  }
}

class SeamLogConfig extends TaintTracking::Configuration {
  SeamLogConfig() { this = "SeamLogInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() = any(SeamLogSource s).getAnArgument()
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SeamLogSink logSink | sink.asExpr() = logSink.getArgument(0))
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // No sanitizers in this rule
    none()
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Argument to parameter propagation
    TaintTracking::localTaintStep(node1, node2) or
    TaintTracking::parameterTaintStep(node1, node2)
  }
}

from SeamLogConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, 
  "Potential Seam log injection vulnerability due to unfiltered input in log expression", 
  source, sink,
  "Untrusted input flows to Seam log expression which could lead to code execution"