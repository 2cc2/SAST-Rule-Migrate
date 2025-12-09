/**
 * @name exec-injection
 * @description Detected user data flowing into exec. This is code injection and should be avoided.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id security/python/exec-injection
 * @tags security
 *       external/cwe/cwe-95
 *       external/owasp/a03
 *       technology/flask
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.frameworks.flask.Flask

class RouteParamSource extends DataFlow::Node {
  RouteParamSource() {
    exists(Method m, string routeVar |
      m.getDoc().regexpMatch("@\\$APP\\.route\\(\\$ROUTE, ...\\)\\n  def \\$FUNC\\(..., \\$ROUTEVAR, ...\\)") and
      m.getParameter(routeVar) = this.asParameter()
    )
  }
}

class FlaskRequestSource extends DataFlow::Node {
  FlaskRequestSource() {
    exists(CallNode call |
      call = this.asExpr() and
      (
        call.getMethod().getName() = "get" or
        call.getMethod().getName() = "__getitem__" or
        call.getMethod().getName() = "__call__"
      ) and
      call.getReceiver().getType().hasQualifiedName("flask.request", "request")
    )
  }
}

class ExecSink extends DataFlow::Node {
  ExecSink() {
    exists(CallNode call |
      call = this.asExpr() and
      call.getMethod().getName() = "exec" and
      call.getReceiver().getType().hasQualifiedName("builtins")
    )
  }
}

config.hasFlowPath(
  DataFlow::sourceNode(RouteParamSource or FlaskRequestSource),
  DataFlow::sinkNode(ExecSink),
  "User data flowing into exec()"
)