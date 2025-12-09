/**
 * @name Use JSTL escaping
 * @description Detected an Expression Language segment in a tag that does not escape output.
 * @kind problem
 * @id use-jstl-escaping
 * @security-severity 8.0
 * @tags security
 *       jsp
 */
import python
import semmle.python.Strings

from StringLiteral unsafeExpr, xssSink
where 
  // Source: Unsafe Expression
  matches(unsafeExpr.getValue(), "<(?![A-Za-z0-9]+:out).*?\\$\\{.*?\\}.*>") and
  // Sink: XSS Sink
  matches(xssSink.getValue(), "\\$\\{.*?\\}")
select unsafeExpr, 
  "Detected an Expression Language segment in a tag that does not escape output. " +
  "This is dangerous because if any data in this expression can be controlled " +
  "externally, it is a cross-site scripting vulnerability. Instead, use the " +
  "'out' tag from the JSTL taglib to escape this expression. " +
  "See https://www.tutorialspoint.com/jsp/jstl_core_out_tag.htm " +
  "for more information."