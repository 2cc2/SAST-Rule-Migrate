/**
 * @name JSP scriptlet detection
 * @description Scriptlets are difficult to use securely and are considered bad practice.
 * @kind problem
 * @id java/jsp/no-scriptlets
 * @security-severity 7.5
 * @problem.severity warning
 * @tags security
 *       jsp
 *       injection
 */

import java

from StringLiteral literal, File f
where matches(literal.getText(), "<\\%[^@].*") 
  and matches(f.getRelativePath(), ".*\\.jsp$")
select literal, "JSP scriptlet detected. Scriptlets are difficult to use securely and are considered bad practice. See https://stackoverflow.com/a/3180202. Instead, consider migrating to JSF or using the Expression Language '${...}' with the escapeXml function in your JSP files."