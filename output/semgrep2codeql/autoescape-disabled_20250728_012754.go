/**
 * @name Auto Escape Disabled in JSF
 * @description Detected an element with disabled HTML escaping. If external data can reach this, 
 *              this is a cross-site scripting (XSS) vulnerability.
 * @kind path-problem
 * @problem.severity warning
 * @id jsf/autoescape-disabled
 * @tags security
 *       external/owasp/a07
 *       external/cwe/cwe-150
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class EscapeDisabled extends DataFlow::Node {
  EscapeDisabled() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("escape%") and
      ma.getArgument(0).toString() = "false" and
      this.asExpr() = ma
    )
  }
}

class ExternalInput extends DataFlow::Node {
  ExternalInput() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("getParameter%") and
      this.asExpr() = ma
    )
  }
}

class EscapeDisabledConfig extends TaintTracking::Configuration {
  EscapeDisabledConfig() { this = "EscapeDisabledConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof ExternalInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof EscapeDisabled }

  override predicate isSanitizer(DataFlow::Node sanitizer) { none() }
}

from EscapeDisabledConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential XSS vulnerability: HTML auto-escaping is disabled for external input"