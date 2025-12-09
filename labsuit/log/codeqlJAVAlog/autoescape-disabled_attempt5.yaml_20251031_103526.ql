/**
 * @name Autoescape Disabled
 * @description Detected an element with disabled HTML escaping. If external data can reach this, 
 *              this is a cross-site scripting (XSS) vulnerability. Ensure no external data can reach 
 *              here, or remove 'escape=false' from this element.
 * @kind problem
 * @id python/security/autoescape-disabled
 * @severity warning
 * @tags security
 *       owasp-a7
 *       cwe-150
 */

import python
import semmle.python.Strings.regex

from StringLiteral node
where matches(node.getValue(), ".*escape.*?=.*?false.*")
select node, "Detected an element with disabled HTML escaping. If external data can reach here, " +
       "this is a cross-site scripting (XSS) vulnerability."