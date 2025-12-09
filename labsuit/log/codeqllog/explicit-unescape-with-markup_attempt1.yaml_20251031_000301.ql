/**
 * @name Explicit unescape with markup
 * @description Detected explicitly unescaped content using 'Markup()'. This permits the unescaped
 *              data to include unescaped HTML which could result in cross-site scripting.
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id python/explicit-unescape-with-markup
 * @tags security
 *       external/cwe/cwe-079
 *       external/owasp/a07:2017
 *       external/owasp/a03:2021
 *       technology/flask
 */

import python
import DataFlow::PathGraph

class FlaskMarkupUnescapeSource extends DataFlow::Node {
  FlaskMarkupUnescapeSource() {
    exists(MethodCall call |
      call.getTarget().hasQualifiedName("flask", "Markup", "unescape") and
      call.getLocation().getFile().getRelativePath().matches("%flask%") and
      this.asExpr() = call
    )
  }
}

class XssSink extends DataFlow::Node {
  XssSink() {
    exists(MethodCall call |
      (
        call.getTarget().hasQualifiedName("flask", "Markup", "__init__") or
        call.getTarget().hasQualifiedName("markupsafe", "Markup", "__init__")
      ) and
      call.getLocation().getFile().getRelativePath().matches("%flask%|%markupsafe%") and
      call.getArg(0).getValue() != "\"\"\"\"" and
      this.asExpr() = call.getArg(0)
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "XSS via Markup unescape" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof FlaskMarkupUnescapeSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof XssSink
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Detected explicitly unescaped content using 'Markup()'. This permits the unescaped " +
       "data to include unescaped HTML which could result in cross-site scripting. " +
       "Ensure this data is not externally controlled, or consider rewriting to not use 'Markup()'."