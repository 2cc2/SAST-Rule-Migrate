/**
 * @name Seam Log Injection
 * @description Seam Logging API supports expression language that can lead to code execution
 * @kind problem
 * @problem.severity error
 * @id java/seam-log-injection
 * @tags security
 *       external/cwe/cwe-95
 *       external/owasp/a03
 */
import codeql.java
import codeql.java.dataflow.FlowSources
import codeql.java.dataflow.TaintTracking
import DataFlow::PathGraph

class SeamLogConfig extends TaintTracking::Configuration {
  SeamLogConfig() { this = "SeamLogInjection" }

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

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      pred.asExpr() = ma and succ.asExpr() = ma.getAnArgument()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, SeamLogConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), "Seam logging expression may evaluate unfiltered input leading to code injection", 
  source.getNode(), "User input source"