/**
 * @name Seam Log Injection
 * @description Detects Seam Logging API calls with potential expression language injection
 * @kind path-problem
 * @problem.severity error
 * @id java/seam-log-injection
 * @tags security
 *       jboss
 *       external/cwe/cwe-95
 *       external/owasp/a03
 */
import java
import semmle.code.java.dataflow.TaintTracking

class SeamLogConfig extends TaintTracking::Configuration {
  SeamLogConfig() { this = "SeamLogInjectionConfig" }

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
}

from DataFlow::PathNode source, DataFlow::PathNode sink, SeamLogConfig config
where config.hasFlowPath(source, sink)
select sink, 
  "Seam Logging API supports expression language which may lead to code execution. The argument is from $@.",
  source, source.toString()