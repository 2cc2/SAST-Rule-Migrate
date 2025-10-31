/**
 * @name autoescape-disabled
 * @description Detected an element with disabled HTML escaping. If external data can reach this, this is a cross-site scripting (XSS) vulnerability. Ensure no external data can reach here, or remove 'escape=false' from this element.
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id python/autoescape-disabled
 * @tags security
 *       owasp:a7
 *       cwe:150
 */

import python

from StringLiteral l
where l.getValue().matches(".*escape.*?=.*?false.*")
select l, "Detected an element with disabled HTML escaping. This could lead to XSS vulnerabilities."