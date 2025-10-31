/**
 * @name eval-injection
 * @description Detected user data flowing into eval. This is code injection and should be avoided.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @tags security
 *       external/cwe/cwe-095
 *       external/owasp/a03
 *       framework/flask
 * @precision medium
 */

import python
import DataFlow::PathGraph

class FlaskRequestSource extends DataFlow::Node {
  FlaskRequestSource() {
    exists(CallNode call |
      call.getTarget().(MethodAccess).getPackage() = "flask" and
      call.getTarget().(MethodAccess).getType() = "request" and
      call.getTarget().hasQualifiedName(["flask", "request"]) |
      this.asSource() = call
    )
  }
}

class RouteParameterSource extends DataFlow::Node {
  RouteParameterSource() {
    exists(ParameterNode p |
      p.getName().regexpMatch("\\$ROUTEVAR") |
      this.asSource() = p
    )
  }
}

class EvalSink extends DataFlow::Node {
  EvalSink() {
    exists(CallNode call |
      call.getTarget().hasQualifiedName(["builtins", "eval"]) |
      this.asSink() = call
    )
  }
}

predicate isSource(DataFlow::Node source) { source instanceof FlaskRequestSource or source instanceof RouteParameterSource }

predicate isSink(DataFlow::Node sink) { sink instanceof EvalSink }

predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
  // Propagation through arguments to parameters
  exists(MethodAccess ma, ParameterNode pn |
    node1.asParameter() = ma.getAnArgument() and
    node2.asParameter() = pn and
    ma.getValue().getAPredecessor+() = pn
  ) or
  // Propagation through intermediate assignments
  node1.asDef() = node2.asUse()
}

query predicate evalInjectionFlow(DataFlow::PathNode source, DataFlow::PathNode sink) {
  source.getNode().isSource() and
  sink.getNode().isSink() and
  hasFlowPath(source, sink)
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where evalInjectionFlow(source, sink)
select sink.getNode(), source.getNode(), source, sink, "Detected user data flowing into eval. This is code injection and should be avoided."