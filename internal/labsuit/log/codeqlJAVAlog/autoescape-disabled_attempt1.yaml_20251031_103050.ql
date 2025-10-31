/** 
 * @name autoescape-disabled
 * @description Detected an element with disabled HTML escaping. If external data can reach this, this is a cross-site scripting (XSS) vulnerability. Ensure no external data can reach here, or remove 'escape=false' from this element.
 * @kind problem
 * @problem.severity warning
 * @id java/autoescape-disabled
 * @tags security
 *       external/cwe/cwe-150
 *       external/owasp/a07:2017
 */
import java

from Literal l
where regexMatches(".*escape.*?=.*?false.*", l.getValue().toString())
select l, "Detected an element with disabled HTML escaping. If external data can reach this, this is a cross-site scripting (XSS) vulnerability. Ensure no external data can reach here, or remove 'escape=false' from this element."