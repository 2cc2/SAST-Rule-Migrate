/**
 * @id autoescape-disabled
 * @name Autoescape disabled detection
 * @description Detected an element with disabled HTML escaping. If external data can reach this, this is a cross-site scripting (XSS) vulnerability.
 * @kind problem
 * @severity warning
 * @precision medium
 * @tags security
 *       owasp-a7
 *       cwe-150
 */

import python

from StringLiteral sl
where sl.getText().regexpMatch(".*escape.*?=.*?false.*")
select sl, "Detected an element with disabled HTML escaping. If external data can reach this, this is a cross-site scripting (XSS) vulnerability. Ensure no external data can reach here, or remove 'escape=false' from this element."