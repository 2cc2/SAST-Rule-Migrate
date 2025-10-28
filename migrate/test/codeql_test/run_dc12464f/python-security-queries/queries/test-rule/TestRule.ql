/**
 * @name Eval Injection
 * @description Detected user data flowing into eval. This is code injection and should be avoided.
 * @kind taint-problem
 * @problem.severity error
 * @id python/eval-injection
 */

import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.dataflow.TaintTracking
import semmle.python.web.Flask

class FlaskRequestInput extends DataFlow::Node {
  FlaskRequestInput() {
    exists(MethodAccess ma |
      ma.getTarget().(FunctionValue).getName().matches("flask.request.%") and
      this.asExpr() = ma
    )
  }
}

class RouteParameterInput extends DataFlow::Node {
  RouteParameterInput() {
    exists(Function f, Parameter p |
      f.getDecoratorName().matches("@.*\.route.*") and
      p = f.getAParameter() and
      this.asParameter() = p
    )
  }
}

class EvalSink extends DataFlow::Node {
  EvalSink() {
    exists(Call call |
      call.getTarget().(FunctionValue).getName() = "eval" and
      call.getArg(0) = this.asExpr()
    )
  }
}

class EvalInjectionConfig extends TaintTracking::Configuration {
  EvalInjectionConfig() { this = "EvalInjection" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof FlaskRequestInput or
    source instanceof RouteParameterInput
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof EvalSink
  }
}

from EvalInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected user data flowing into eval. This is code injection and should be avoided."