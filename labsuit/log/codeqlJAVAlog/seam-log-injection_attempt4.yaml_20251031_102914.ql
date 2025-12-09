/**
 * @name Seam Log Injection
 * @description Seam Logging API support an expression language to introduce bean property to log messages.
 *              The expression language can also be the source to unwanted code execution.
 *              In this context, an expression is built with a dynamic value.
 *              The source of the value(s) should be verified to avoid that unfiltered values fall into this risky
 *              code evaluation.
 * @kind path-problem
 * @problem.severity error
 * @id java/seam-log-injection
 * @tags security
 *       jboss
 * @cwe CWE-95
 * @owasp A03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow

class SeamLogConfig extends TaintTracking::Configuration {
  SeamLogConfig() { this = "SeamLogInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("org.jboss.seam.log.Log", ["debug", "error", "fatal", "info", "trace", "warn"]) and
      source.asExpr() = ma.getAnArgument()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("org.jboss.seam.log.Log", ["debug", "error", "fatal", "info", "trace", "warn"]) and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      succ.asExpr() = ma.getAnArgument() and
      pred.asExpr().(MethodAccess).getMethod() = ma.getMethod()
    )
  }
}

from SeamLogConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential Seam log injection due to unfiltered input in $@.",
  source.getNode(), "user-provided value"