/**
 * @name Path traversal in open() call
 * @description Detects path traversal vulnerabilities when user input flows into file open operations.
 * @kind path-problem
 * @id python/path-traversal-open
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @tags security
 *       external/cwe/cwe-022
 *       external/owasp/a05:2017
 *       external/owasp/a01:2021
 */

import python
import semmle.python.dataflow.TaintTracking
import DataFlow::PathGraph

class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() { this = "PathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Route variables ($ROUTEVAR)
    exists(Parameter p |
      p.getAnnotatedName().regexpMatch("^\\$ROUTEVAR$") and
      source.asParameterNode() = p
    )
    or
    // Flask request methods
    exists(Call call |
      call.getCallee().getQualifiedName().regexpMatch("flask\\.request\\.[^.]+") and
      source.asExpr() = call
    )
    or
    // Intermediate variables containing request data
    exists(DataFlow::Node src, LocalVariable v |
      (hasRouteVarSource(src) or hasFlaskRequestSource(src)) and
      DataFlow::localFlow(src, source.asDef()) and
      source.asDef() = v
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getCallee().getName() = "open" and
      sink.asExpr() = call.getArg(0)
    )
  }

  private predicate hasRouteVarSource(DataFlow::Node source) {
    exists(Parameter p |
      p.getAnnotatedName().regexpMatch("^\\$ROUTEVAR$") and
      source.asParameterNode() = p
    )
  }

  private predicate hasFlaskRequestSource(DataFlow::Node source) {
    exists(Call call |
      call.getCallee().getQualifiedName().regexpMatch("flask\\.request\\.[^.]+") and
      source.asExpr() = call
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Handle field accesses
    exists(FieldAccess fa |
      node1.asExpr() = fa.getObject() and
      node2.asExpr() = fa
    )
    or
    // Handle array accesses
    exists(ArrayExpr ae |
      node1.asExpr() = ae.getArray() and
      node2.asExpr() = ae
    )
    or
    // Handle assignment propagation
    DataFlow::localFlow(node1, node2)
  }
}

from PathTraversalConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlow(source, sink)
select sink, source, sink,
  "Found request data in a call to 'open'. Ensure the request data is validated or sanitized, otherwise it could result in path traversal attacks."