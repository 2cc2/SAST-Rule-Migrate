/**
 * @name Unsafe JSTL Expression Detection
 * @description Detects Expression Language segments in tags that don't escape output
 * @kind problem
 * @id py/unsafe-jstl-expression
 * @severity WARNING
 * @tags security
 *       jsp
 * @precision high
 */

import python
import DataFlow::PathGraph

class UnsafeExpression extends DataFlow::Node {
  UnsafeExpression() {
    exists(string literal |
      literal = this.asDefiningArgument().getStringValue() |
      literal.regexpMatch("<(?![A-Za-z0-9]+:out).*?\\$\\{.*?\\}.*>")
    )
  }
}

class XssSink extends DataFlow::Node {
  XssSink() {
    exists(string literal |
      literal = this.asDefiningArgument().getStringValue() |
      literal.regexpMatch("\\$\\{.*?\\}")
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  source instanceof UnsafeExpression and
  sink instanceof XssSink and
  source.getNode() = sink.getNode()
select sink, "Detected an Expression Language segment in a tag that does not escape " +
  "output. This is dangerous because if any data in this expression can be " +
  "controlled externally, it is a cross-site scripting vulnerability. Instead, " +
  "use the 'out' tag from the JSTL taglib to escape this expression."