/**
 * @name Unsafe JSTL Expression Detection
 * @description Detects Expression Language segments in tags that don't escape output
 * @kind problem
 * @id py/unsafe-jstl-expression
 * @security-severity 7.5
 * @tags security
 *       jsp
 * @precision high
 */

import python
import semmle.code.strings.Strings

class UnsafeExpression extends Str {
  UnsafeExpression() {
    this.matches(/<(?![A-Za-z0-9]+:out).*?\$\{.*?\}.*>/)
  }
}

class XssSink extends Str {
  XssSink() {
    this.matches(/\$\{.*?\}/)
  }
}

from UnsafeExpression expr, XssSink sink
where sink = expr
select sink, "Detected an Expression Language segment in a tag that does not escape " +
  "output. This is dangerous because if any data in this expression can be " +
  "controlled externally, it is a cross-site scripting vulnerability. Instead, " +
  "use the 'out' tag from the JSTL taglib to escape this expression."