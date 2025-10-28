/**
 * @name Path Traversal via open() with Unsanitized Request Data
 * @description Detects when Flask request data flows into open() call without sanitization,
 *              which could lead to path traversal attacks.
 * @kind path-problem
 * @problem.severity error
 * @id py/path-traversal-open
 */

import python
import semmle.python.security.dataflow.TaintTracking
import semmle.python.web.flask.FlaskRequest
import semmle.python.Concepts

class FlaskRequestSource extends DataFlow::NodeSrc {
  FlaskRequestSource() {
    exists(MethodAccess ma |
      ma.getMethodQualifiedName().regexpMatch("flask\\.request\\..*") and
      result.asExpr() = ma
    )
  }
}

class RouteVariableSource extends DataFlow::NodeSrc {
  RouteVariableSource() {
    exists(Variable v |
      v.getName().regexpMatch("\\$ROUTEVAR|\\$INTERM") and
      result.asExpr() = v
    )
  }
}

class FileOpenSink extends DataFlow::NodeSink {
  FileOpenSink() {
    exists(FunctionCall fc |
      fc.getTarget().getName() = "open" and
      result.asExpr() = fc.getAnArgument()
    )
  }
}

class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() {
    this = "PathTraversalConfig"
  }

  override predicate isSource(DataFlow::Node source) {
    source instanceof FlaskRequestSource or
    source instanceof RouteVariableSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileOpenSink
  }
}

from PathTraversalConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Found request data in a call to 'open'. Ensure the request data is " +
  "validated or sanitized, otherwise it could result in path traversal attacks."