/**
 * @id use-jstl-escaping
 * @severity WARNING
 * @description Detected an Expression Language segment in a tag that does not escape
 *    output. This is dangerous because if any data in this expression
 *    can be controlled externally, it is a cross-site scripting
 *    vulnerability. Instead, use the 'out' tag from the JSTL taglib
 *    to escape this expression.
 *    See https://www.tutorialspoint.com/jsp/jstl_core_out_tag.htm
 *    for more information.
 * @tags security, jsp
 */

import python
import semmle.python.Strings

from Str s
where 
  s.getText().regexpMatch("<(?![A-Za-z0-9]+:out).*?\\$\\{.*?\\}.*>") and
  s.getText().regexpMatch("\\$\\{.*?\\}")
select s, 
  "Detected an unsafe Expression Language segment without output escaping. Use JSTL out tag instead.",
  s.getLocation()