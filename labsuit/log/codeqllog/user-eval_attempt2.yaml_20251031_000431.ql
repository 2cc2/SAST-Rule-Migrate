/**
 * @name Eval Injection
 * @description Detected user data flowing into eval. This is code injection and should be avoided.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision medium
 * @id py/eval-injection
 * @tags security
 *       external/cwe/cwe-95
 *       external/owasp/a03
 */

import python
import semmle.python.dataflow.DataFlow
import semmle.python.ApiGraphs
import semmle.python.Concepts

class RouteParameterSource extends DataFlow::ParameterNode {
  RouteParameterSource() {
    this.getVariableName().regex("\$ROUTEVAR")
  }
}

class FlaskRequestSource extends DataFlow::Node {
  FlaskRequestSource() {
    exists(CallNode call |
      call = DataFlow::moduleImport("flask").getMember("request").getACall()
      and this.asSource() = call
    )
  }
}

class EvalSink extends DataFlow::CallNode {
  EvalSink() {
    exists(CallNode call |
      call.getACallee().getName() = "eval" 
      and this.asSink() = call
    )
  }
}

query predicate isSource(DataFlow::Node source) {
  source instanceof RouteParameterSource
  or
  source instanceof FlaskRequestSource
}

query predicate isSink(DataFlow::Node sink) {
  sink instanceof EvalSink
}

query predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
  (exists(DataFlow::AssignmentNode assign |
    assigns(node1, node2, assign)
  ))
  or
  (exists(DataFlow::ArgToParam arg |
    argToParam(node1, node2, arg)
  ))
}

from DataFlow::Node source, DataFlow::Node sink
where isSource(source) and isSink(sink) and DataFlow::localFlow(source, sink)
select sink, "Potential eval injection from untrusted source $@.", source, source.toString()