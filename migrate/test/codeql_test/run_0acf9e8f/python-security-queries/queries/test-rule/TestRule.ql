/**
 * @name Execution Injection
 * @description Detected user data flowing into exec. This is code injection and should be avoided.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id py/exec-injection
 * @tags security
 *       external/cwe/cwe-095
 *       external/cwe/cwe-079
 *       external/owasp/a03
 */
import python
import semmle.python.DataFrame
import python.flask.Flask

class RouteParamSource extends DataFrame::Node::Range {
  RouteParamSource() {
    exists(Function f, Name name |
      f.getADecorator().getName() = "route" and
      this = f.getAParameter().getAnAccess()
    )
  }
}

class FlaskRequestSource extends DataFrame::Node::Range {
  FlaskRequestSource() {
    exists(CallNode call |
      call.getCallee().(NameNode).getId() = ["get", "__getitem__", "__call__"] and
      call.getCallee().getParentScope().getName() = "request" and
      this = call.getAnArgument()
    )
  }
}

class ExecSink extends DataFrame::Node::Range {
  ExecSink() {
    exists(CallNode call |
      call.getCallee().(NameNode).getId() = "exec" and
      this = call.getArgument(0)
    )
  }
}

predicate isSource(DataFrame::Node::Range node) {
  node instanceof RouteParamSource or
  node instanceof FlaskRequestSource
}

predicate isSink(DataFrame::Node::Range node) {
  node instanceof ExecSink
}

from DataFrame::Configuration config, DataFrame::Node::Range source, DataFrame::Node::Range sink
where
  config.hasFlowPath(source, sink) and
  isSource(source) and
  isSink(sink)
select sink, "Potential code injection vulnerability due to user input reaching exec()", source,
  "User input flows to exec() here"