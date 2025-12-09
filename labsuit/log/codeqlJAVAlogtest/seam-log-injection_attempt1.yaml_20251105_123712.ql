/**
 * @name Seam Log Injection
 * @description Seam Logging API supports expression language that can lead to code execution.
 * @kind taint
 * @problem.severity error
 * @security-severity 8.8
 * @id java/seam-log-injection
 * @tags security
 *       jboss
 *       injection
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class SeamLogMethod extends Method {
  SeamLogMethod() {
    this.getDeclaringType().getQualifiedName() = "org.jboss.seam.log.Log" and
    this.getName() in ["debug", "error", "fatal", "info", "trace", "warn"]
  }
}

class SeamLogSource extends DataFlow::Node {
  SeamLogSource() {
    exists(MethodAccess ma | 
      ma.getMethod() instanceof SeamLogMethod and 
      this.asExpr() = ma
    )
  }
}

class SeamLogSink extends DataFlow::Node {
  SeamLogSink() {
    exists(MethodAccess ma | 
      ma.getMethod() instanceof SeamLogMethod and
      ma.getArgument(0) = this.asExpr()
    )
  }
}

class SeamLogTaintTrackingConfig extends TaintTracking::Configuration {
  SeamLogTaintTrackingConfig() { this = "SeamLogTaintTrackingConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SeamLogSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SeamLogSink
  }
}

from SeamLogTaintTrackingConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential log injection vulnerability due to dynamic content in Seam log expression."