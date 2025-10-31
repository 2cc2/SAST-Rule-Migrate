/**
 * @name Exec Injection Vulnerability
 * @description Detects user data flowing into exec calls (Python code injection)
 * @kind path-problem
 * @problem.severity error
 * @id py/exec-injection
 * @tags security
 *       external/cwe/cwe-95
 *       external/owasp/a03
 */

import python
import python.frameworks.flask
import DataFlow::PathGraph

class RouteParamSource extends DataFlow::Node {
  RouteParamSource() {
    exists(Function f |
      f.getADecoratorName() = "route" and
      this.asParameter() = f.getAParameter()
    )
  }
}

class FlaskRequestSource extends DataFlow::Node {
  FlaskRequestSource() {
    exists(CallNode call |
      call.getFunc().(Name).getId() = ["get", "__getitem__", "__call__"] and
      call.getArg(0).(Expr) = this.asExpr() and
      call.getFunc().getQualifier().matches("flask.request")
    )
  }
}

class ExecSink extends DataFlow::Node {
  ExecSink() {
    exists(CallNode call |
      call.getFunc().(Name).getId() = "exec" and
      call.getArg(0).(Expr) = this.asExpr()
    )
  }
}

predicate isSource(DataFlow::Node source) {
  source instanceof RouteParamSource or
  source instanceof FlaskRequestSource
}

predicate isSink(DataFlow::Node sink) {
  sink instanceof ExecSink
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where DataFlow::flowPath(source, sink)
select sink.getNode(), "Detected user data flowing into exec. This is code injection and should be avoided.",
  source.getNode(), "User input source"