/**
 * @name Use JSTL escaping
 * @description Detected an Expression Language segment in a tag that does not escape
 *     output. This is dangerous because if any data in this expression
 *     can be controlled externally, it is a cross-site scripting
 *     vulnerability. Instead, use the 'out' tag from the JSTL taglib
 *     to escape this expression.
 * @kind problem
 * @problem.severity warning
 * @id security/jsp/use-jstl-escaping
 * @tags security
 *   jsp
 */
   
import java
import Regex

from Literal lit
where 
  // Source pattern: matches unsafe JSP expressions not using JSTL out tag
  regexMatches("<(?![A-Za-z0-9]+:out).*?\\$\\{.*?\\}.*>", lit.getValue().toString()) and
  // Sink pattern: matches any Expression Language segment
  regexMatches("\\$\\{.*?\\}", lit.getValue().toString())
select lit, 
  "Detected an Expression Language segment in a tag that does not escape output. " +
  "This is dangerous because if any data in this expression can be controlled externally, " +
  "it is a cross-site scripting vulnerability. Instead, use the 'out' tag from the JSTL " +
  "taglib to escape this expression."