/**
 * @id autoescape-disabled
 * @severity WARNING
 * @message Detected an element with disabled HTML escaping. If external data can reach this, this is a cross-site scripting (XSS) vulnerability. Ensure no external data can reach here, or remove 'escape=false' from this element.
 * @tags security
 * @precision LOW
 */

import python
import semmle.python.regex.Regexp

from StringLiteral node
where regexpMatch(node.getText(), ".*escape.*?=.*?false.*")
select node, "Detected an element with disabled HTML escaping. This may be vulnerable to cross-site scripting (XSS)."