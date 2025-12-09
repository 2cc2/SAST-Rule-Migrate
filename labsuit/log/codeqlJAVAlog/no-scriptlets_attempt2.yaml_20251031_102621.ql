/**
 * @name JSP scriptlet detected
 * @description Scriptlets are difficult to use securely and are considered bad practice.
 *              Consider migrating to JSF or using the Expression Language '${...}' with the escapeXml function.
 * @kind problem
 * @problem.severity warning
 * @id no-scriptlets
 * @tags security
 *       jsp
 *       injection
 */

import java
import java.regex.Pattern

from StringLiteral scriptlet, File f
where 
  Pattern.matches("\\<%[^@].*", scriptlet.getStringValue()) and
  Pattern.matches(".*\\.jsp$", f.getBaseName())
select scriptlet, "JSP scriptlet detected. Scriptlets are difficult to use securely and are considered bad practice. " +
  "See https://stackoverflow.com/a/3180202. Instead, consider migrating to JSF or using " +
  "the Expression Language '${...}' with the escapeXml function in your JSP files."