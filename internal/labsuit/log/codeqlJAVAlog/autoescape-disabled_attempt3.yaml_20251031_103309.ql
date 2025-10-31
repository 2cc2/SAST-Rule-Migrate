/**
 * @name Autoescape disabled
 * @description Detected an element with disabled HTML escaping. If external data can reach this, this is a cross-site scripting (XSS) vulnerability.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision low
 * @id autoescape-disabled
 * @tags security
 *       external/cwe/cwe-150
 *       owasp-a7
 */
import python

from StringLiteral node
where regexMatches(node.getStringValue(), ".*escape.*?=.*?false.*")
select node, "Detected an element with disabled HTML escaping. If external data can reach this, this is a cross-site scripting (XSS) vulnerability. Ensure no external data can reach here, or remove 'escape=false' from this element."