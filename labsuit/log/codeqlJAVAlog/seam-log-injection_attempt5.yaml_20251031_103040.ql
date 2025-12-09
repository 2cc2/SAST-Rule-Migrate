/**
 * @name Seam Log Injection
 * @description Seam Logging API support an expression language to introduce bean property to log messages.
 *              The expression language can also be the source to unwanted code execution.
 *              In this context, an expression is built with a dynamic value.
 *              The source of the value(s) should be verified to avoid that unfiltered values fall into this risky
 *              code evaluation.
 * @kind path-problem
 * @problem.severity error
 * @id jboss/seam-log-injection
 * @tags security
 *       jboss
 * @cwe CWE-95
 * @owasp A03:2021
 */

import java
import DataFlow::PathGraph
import DataFlow::TaintTracking
import semmle.code.java.frameworks.Logging

class SeamLogConfig extends TaintTracking::Configuration {
  SeamLogConfig() { this = "SeamLogConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["debug", "error", "fatal", "info", "trace", "warn"]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.jboss.seam.log", "Log") and
      source.asExpr() = ma
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["debug", "error", "fatal", "info", "trace", "warn"]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.jboss.seam.log", "Log") and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma |
      ma.getArgument(_) = node1.asExpr() and
      ma = node2.asExpr()
    )
  }
}

from SeamLogConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Seam Log injection from $@.", source.getNode(),
  "User provided input"