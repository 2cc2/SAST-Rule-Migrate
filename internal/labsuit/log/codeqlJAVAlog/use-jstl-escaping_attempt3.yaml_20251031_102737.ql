/**
 * @name Use JSTL Output Escaping
 * @description Detected an Expression Language segment in a tag that does not escape output.
 *              This is dangerous because if any data in this expression can be controlled
 *              externally, it is a cross-site scripting vulnerability.
 * @id use-jstl-escaping
 * @kind problem
 * @severity warning
 * @security-severity 8.0
 * @precision high
 * @tags security
 *       jsp
 * @reference https://www.tutorialspoint.com/jsp/jstl_core_out_tag.htm
 * @reference https://stackoverflow.com/a/4948856
 * @reference https://stackoverflow.com/a/3180202
 */

import java
import semmle.code.java.Strings

from StringLiteralExpr unsafeExpr, StringLiteralExpr xssSink
where 
  // Match unsafe expressions (not using jstl:out)
  unsafeExpr.getLiteral().regexpMatch("<(?![A-Za-z0-9]+:out).*?\\$\\{.*?\\}.*>") and
  // Match potential XSS sinks (expression language)
  xssSink.getLiteral().regexpMatch("\\$\\{.*?\\}") and
  // Flow from unsafe expression to XSS sink
  unsafeExpr = xssSink
select unsafeExpr, 
  "Detected an Expression Language segment in a tag that does not escape output. " +
  "This is dangerous because if any data in this expression can be controlled " +
  "externally, it is a cross-site scripting vulnerability. Instead, use the 'out' " +
  "tag from the JSTL taglib to escape this expression."