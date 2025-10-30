/**
 * @name Explicit Unescape with Markup Detection
 * @kind problem
 * @id python/explicit-unescape-with-markup
 * @problem.severity warning
 * @description Detected explicitly unescaped content using 'Markup()'. 
 *              This permits the unescaped data to include unescaped HTML which could result in cross-site scripting.
 *              Ensure this data is not externally controlled, or consider rewriting to not use 'Markup()'.
 */

import python
import semmle.python.dataflow.TaintTracking
import semmle.python.ApiGraphs

class MarkupUnescapeSource extends DataFlow::Node {
  MarkupUnescapeSource() {
    exists(Call call |
      call.getFunc().getName() = "unescape" and
      call.getFunc().getDeclaringClass().getName() = "Markup" and
      this.asExpr() = call.getArg(0)
    )
  }
}

class MarkupConstructorSink extends DataFlow::Node {
  MarkupConstructorSink() {
    exists(Call call |
      call.getConstructedClass().getName() = "Markup" and
      this.asExpr() = call.getArg(0)
    )
  }
}

class ExplicitUnescapeConfiguration extends TaintTracking::Configuration {
  ExplicitUnescapeConfiguration() { this = "ExplicitUnescapeConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof MarkupUnescapeSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MarkupConstructorSink
  }
}

from ExplicitUnescapeConfiguration cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Detected explicitly unescaped content using 'Markup()' that may lead to XSS"