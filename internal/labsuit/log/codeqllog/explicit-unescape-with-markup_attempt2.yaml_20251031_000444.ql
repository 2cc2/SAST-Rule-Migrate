/**
 * @name Explicit unescape with markup
 * @description Detected explicitly unescaped content using 'Markup()'. This permits 
 * the unescaped data to include unescaped HTML which could result in cross-site scripting. 
 * Ensure this data is not externally controlled, or consider rewriting to not use 'Markup()'.
 * @kind path-problem
 * @problem.severity warning
 * @id python/explicit-unescape-with-markup
 * @tags security
 *       external/cwe/cwe-079
 *       external/owasp/a07:2017
 *       external/owasp/a03:2021
 */

import semmle.python.dataflow.DataFlow
import semmle.python.dataflow.TaintTracking
import semmle.python.Concepts

class FlaskMarkupUnescapeSource extends DataFlow::Node::Range {
  FlaskMarkupUnescapeSource() {
    exists(MethodCall mc |
      mc.getMethod().getName() = "unescape" and
      mc.getReceiver().getType().getName() = "Markup" and
      mc.getFile().getRelativePath().matches("%flask%")
    )
    and
    this = MethodCall.getACall().getResult()
  }
}

class XssSink extends DataFlow::Node::Range {
  XssSink() {
    exists(MethodCall mc |
      mc.getMethod().getName() = "__init__" and
      mc.getReceiver().getType().getName() = "Markup" and
      (mc.getFile().getRelativePath().matches("%flask%") or 
       mc.getFile().getRelativePath().matches("%markupsafe%")) and
      mc.getArgument(0).getValue() != "\"\"\""
    )
    and
    this = MethodCall.getACall().getArgument(0)
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "XSS via Flask.Markup" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof FlaskMarkupUnescapeSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof XssSink
  }
}

from Config cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Detected explicitly unescaped content using '$@'. This may lead to XSS vulnerabilities.",
  source, source.toString()