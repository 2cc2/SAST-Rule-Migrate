/**
 * @name JSP scriptlet detected
 * @description Scriptlets are difficult to use securely and are considered bad practice.
 * @kind problem
 * @severity warning
 * @id security/jsp-scriptlet
 * @tags security
 *       jsp
 *       injection
 */

import python
import semmle.python.Parser

from StringLiteral literal, File f
where regexpMatch(literal.getValue(), "\<\%[^\@].*")
  and regexpMatch(f.getBaseName(), ".*\.jsp$")
select literal, "JSP scriptlet detected. Scriptlets are difficult to use securely and are considered bad practice. See https://stackoverflow.com/a/3180202. Instead, consider migrating to JSF or using the Expression Language '${...}' with the escapeXml function in your JSP files."