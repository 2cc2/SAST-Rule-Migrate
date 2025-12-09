/**
 * @id use-jstl-escaping
 * @severity WARNING
 * @message Detected an Expression Language segment in a tag that does not escape
 *     output. This is dangerous because if any data in this expression
 *     can be controlled externally, it is a cross-site scripting
 *     vulnerability. Instead, use the 'out' tag from the JSTL taglib
 *     to escape this expression.
 *     See [https://www.tutorialspoint.com/jsp/jstl_core_out_tag.htm](https://www.tutorialspoint.com/jsp/jstl_core_out_tag.htm)
 *     for more information.
 */

import java
import semmle.code.strings.StringFormat

class UnsafeExpression extends StringLiteral {
  UnsafeExpression() {
    regexpMatch("<(?![A-Za-z0-9]+:out).*?\\$\\{.*?\\}.*>", this.getValue())
  }
}

class XssSink extends StringLiteral {
  XssSink() {
    regexpMatch("\\$\\{.*?\\}", this.getValue())
  }
}

from XssSink sink
select sink, "Potential XSS vulnerability found in unescaped Expression Language segment. Use JSTL 'out' tag for proper escaping."