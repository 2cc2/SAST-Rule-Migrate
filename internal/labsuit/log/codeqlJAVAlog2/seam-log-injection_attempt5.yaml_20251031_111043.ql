/**
 * @name Seam Log Injection
 * @description Seam Logging API support an expression language to introduce bean property to log messages.
 *              The expression language can also be the source to unwanted code execution.
 *              In this context, an expression is built with a dynamic value.
 *              The source of the value(s) should be verified to avoid that unfiltered values 
 *              fall into this risky code evaluation.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @id java/seam-log-injection
 * @tags security
 *       external/cwe/cwe-095
 *       external/owasp/a03
 *       jboss
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow

class SeamLogCall extends Expr {
  SeamLogCall() {
    exists(MethodAccessExpr ma | 
      ma.getMethod().getDeclaringType().hasQualifiedName("org.jboss.seam.log", "Log") and
      ma.getMethod().hasName(["debug", "error", "fatal", "info", "trace", "warn"]) and
      this = ma
    )
  }
}

class LogSource extends DataFlow::Node {
  LogSource() {
    exists(SeamLogCall call |
      this.asExpr() = call.getArgument(_)
    )
  }
}

class LogSink extends DataFlow::Node {
  LogSink() {
    exists(SeamLogCall call |
      this.asExpr() = call.getArgument(0)
    )
  }
}

class LogTaintConfig extends TaintTracking::Configuration {
  LogTaintConfig() { this = "LogTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof LogSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof LogSink
  }
}

from LogTaintConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, "Potential unsafe log injection in JBoss Seam logging call", source, sink,
  "This logging call uses potentially dangerous dynamic input that could lead to expression injection."