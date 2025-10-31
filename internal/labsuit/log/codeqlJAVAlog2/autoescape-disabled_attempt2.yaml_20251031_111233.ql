/**
 * @name autoescape-disabled
 * @description Detected an element with disabled HTML escaping. If external data can reach this, this is a cross-site scripting (XSS) vulnerability. Ensure no external data can reach here, or remove 'escape=false' from this element.
 * @kind pattern
 * @problem.severity warning
 * @security-severity 5.0
 * @id python/xss-autoescape-disabled
 * @tags security
 *       external/cwe/cwe-150
 *       external/owasp/a07:2017
 */
import python

from StringLiteral literal
where literal.getValue().regexpMatch(".*escape.*?=.*?false.*")
select literal, "Detected an element with disabled HTML escaping. This may be vulnerable to XSS."