/**
 * @name NaN Injection Vulnerability
 * @description Detects when user input goes directly into typecast for bool(), float(), or complex()
 * @kind path-problem
 * @problem.severity error
 * @id python/nan-injection
 */

import semmle.python.dataflow.DataFlow
import semmle.python.dataflow.TaintTracking
import semmle.python.Builtins

class NaNInjectionConfig extends TaintTracking::Configuration {
  NaNInjectionConfig() { this = "NaNInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("flask", "request", "get") and
      source.asExpr() = call
    )
    or
    exists(Method m |
      m.getADecorator().getName() = "route" and
      source.asParameter() = m.getAParameter()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Builtin::Function fn |
      (fn.hasName("float") or fn.hasName("bool") or fn.hasName("complex")) and
      sink.asExpr() = fn.getACall()
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() instanceof Call
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Function f, Parameter p |
      node1.asExpr() = f.getACall().getAnArg() and
      node2.asParameter() = p and
      p = f.getAParameter()
    )
  }
}

from NaNInjectionConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlowPath(source, sink)
select sink, "Found user input going directly into typecast for bool(), float(), or complex(). This allows an attacker to inject Python's not-a-number (NaN) into the typecast."