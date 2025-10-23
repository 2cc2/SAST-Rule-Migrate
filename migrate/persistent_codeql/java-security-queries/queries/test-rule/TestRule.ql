/**
 * @name Seam Log Injection
 * @description Seam Logging API supports expression language which may lead to code injection when dynamic values are used without validation.
 * @kind path-problem
 * @problem.severity error
 * @id java/seam-log-injection
 * @tags security
 *       external/jboss
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class SeamLogMethod extends Method {
  SeamLogMethod() {
    this.getDeclaringType().getQualifiedName() = "org.jboss.seam.log.Log" and
    this.getName().matches("debug|error|fatal|info|trace|warn")
  }
}

class LogCall extends Call {
  LogCall() {
    exists(SeamLogMethod m | this.getCallee() = m)
  }
}

class SeamLogInjectionConfig extends TaintTracking::Configuration {
  SeamLogInjectionConfig() { this = "SeamLogInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Expr e | source.asExpr() = e | e instanceof Literal or e instanceof VariableAccess)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(LogCall lc | sink.asExpr() = lc.getArgument(0))
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess mc |
      node1.asExpr() = mc.getArgument(0) and
      node2.asExpr() = mc
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, SeamLogInjectionConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), 
  "Unfiltered dynamic value reaches Seam Logging API which may evaluate expressions",
  source.getNode(), "Dynamic value from here",
  sink.getNode(), "Flows to seam log API call here"