/**
 * @name exec-injection
 * @description Detected user data flowing into exec. This is code injection and should be avoided.
 * @kind path-problem
 * @problem.severity error
 * @id py/exec-injection
 */

import python
import semmle.python.dataflow.TaintTracking
import semmle.python.web.flask.FlaskRequests

class ExecInjectionConfig extends TaintTracking::Configuration {
  ExecInjectionConfig() { this = "ExecInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Source 1: Route parameters matching regex pattern
    exists(Parameter p |
      source.asParameter() = p and
      regexpMatches(p.getName(), "\\$ROUTEVAR|\\$INTERM")
    )
    or
    // Source 2: Flask request methods
    exists(API::MethodAccess ma, API::Call call |
      call.getTarget() = ma and
      ma.getPackage() = "flask.request" and
      ma.getName() in ["get", "__getitem__", "__call__"] and
      source = call
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(API::Call call |
      call.getTarget().getName() = "exec" and
      sink.asExpr() = call.getAnArgument()
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) { none() }
}

from ExecInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink,
  "Detected user data flowing into exec. This is code injection and should be avoided."