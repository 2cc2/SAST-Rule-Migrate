/**
 * @name JSP scriptlet detection
 * @description JSP scriptlet detected. Scriptlets are difficult to use securely and are considered bad practice.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @id java/no-scriptlets
 * @tags security
 *       jsp
 *       injection
 */

import java

from Literal l, File f
where 
  l.getValue().matches("<%[^@].*") and
  f.getLocation().getFile().getBaseName().matches(".*\\.jsp$") and
  f.getLocation().getFile() = l.getLocation().getFile()
select l, "JSP scriptlet detected. Scriptlets are difficult to use securely and are considered bad practice. See $@. Instead, consider migrating to JSF or using the Expression Language '${...}' with the escapeXml function in your JSP files.",
  l, "https://stackoverflow.com/a/3180202"