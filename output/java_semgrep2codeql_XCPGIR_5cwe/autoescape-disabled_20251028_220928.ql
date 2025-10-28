/**
 * @name autoescape-disabled
 * @description Detected an element with disabled HTML escaping. If external data can reach this, this is a cross-site scripting (XSS) vulnerability.
 * @kind path-problem
 * @problem.severity warning
 * @id jsf/autoescape-disabled
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.StringFormat

class DisabledEscape extends DataFlow::Node {
  DisabledEscape() {
    exists(StringLiteral s |
      s.getValue().regexpMatch(".*escape.*?=.*?false.*") and
      this.asExpr() = s
    )
  }
}

class XssSink extends DataFlow::Node {
  XssSink() {
    exists(Call call | this.asExpr() = call)
  }
}

query predicate isFlow(DataFlow::Node source, DataFlow::Node sink) {
  exists(DisabledEscape disabledEscape, XssSink xssSink |
    source = disabledEscape and
    sink = xssSink and
    DataFlow::localFlow(source, sink)
  )
}

from DataFlow::Node source, DataFlow::Node sink
where isFlow(source, sink)
select sink, 
  "Detected an element with disabled HTML escaping. Potential XSS vulnerability.",
  source, "Disabled HTML escaping here",
  sink, "Potentially dangerous location"