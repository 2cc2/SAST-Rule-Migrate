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
import semmle.python.Strings

class UnsafeExpression extends string::Literal {
  UnsafeExpression() {
    this.getValue().regexpMatch("<(?![A-Za-z0-9]+:out).*?\\$\\{.*?\\}.*>")
  }
}

class XssSink extends string::Literal {
  XssSink() {
    this.getValue().regexpMatch("\\$\\{.*?\\}")
  }
}

from UnsafeExpression expr, XssSink sink
where sink.getValue() = expr.getValue()
select sink, "Detected an Expression Language segment in a tag that does not escape " +
  "output. This is dangerous because if any data in this expression can be " +
  "controlled externally, it is a cross-site scripting vulnerability. Instead, " +
  "use the 'out' tag from the JSTL taglib to escape this expression."