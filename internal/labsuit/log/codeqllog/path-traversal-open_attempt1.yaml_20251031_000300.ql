/**
 * @name Path Traversal via open()
 * @description Detects request data in calls to open() that could lead to path traversal attacks
 * @kind path-problem
 * @problem.severity error
 * @id py/path-traversal-open
 * @tags security
 *       external/cwe/cwe-22
 *       external/owasp/a05:2017
 *       external/owasp/a01:2021
 */
import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.dataflow.TaintTracking
import semmle.python.dataflow.new.RemoteUserInput

class PathTraversalOpenConfig extends TaintTracking::Configuration {
  PathTraversalOpenConfig() { this = "PathTraversalOpenConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Source 1: Flask route parameters
    exists(MethodParam param |
      param.getAnnotatedName().regexpMatch("^\\$ROUTEVAR$") and
      source.asParameter() = param
    )
    or
    // Source 2: Flask request calls
    exists(Call call |
      call.getTarget().hasQualifiedName("flask", "request", "*") and
      source.asExpr() = call
    )
    or
    // Source 3: Variables assigned from flask.request or route parameters
    exists(LocalVariable var, Expr assignmentSource |
      DataFlow::localVarDef(var, assignmentSource) and
      assignmentSource.toString().matches("%flask%.request%") and
      source.asExpr() = var.getAUse()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getTarget().hasQualifiedName("__builtin__", "open") and
      sink.asExpr() = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    none()
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Propagation for argument passing
    exists(Call call, int argIndex |
      call.getArgument(argIndex) = node1.asExpr() and
      node2.asParameter() = call.getTarget().getAParameter(argIndex)
    )
    or
    // Propagation for field accesses
    exists(FieldRead read |
      read.getFieldAccess() = node1.asExpr() and
      read = node2.asExpr()
    )
    or
    // Propagation for array accesses
    exists(ArrayAccess access |
      access.getArray() = node1.asExpr() and
      access = node2.asExpr()
    )
    or
    // Propagation for alias assignments
    exists(LocalVariable var |
      DataFlow::localVarDef(var, node1.asExpr()) and
      node2.asExpr() = var.getAUse()
    )
  }
}

from PathTraversalOpenConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, 
"A path traversal vulnerability may exist here when opening files with untrusted input $@.", source,
"from this user input"