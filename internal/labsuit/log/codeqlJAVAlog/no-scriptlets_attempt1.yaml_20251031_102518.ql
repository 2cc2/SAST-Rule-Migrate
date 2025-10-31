/**
 * @name JSP scriptlet detection
 * @description JSP scriptlet detected. Scriptlets are difficult to use securely and are considered bad practice. 
 * @kind problem
 * @problem.severity warning
 * @id java/no-scriptlets
 * @tags security
 *       jsp
 *       injection
 */

import java
import Regex

from Literal l, File f
where 
  l.getValue().regex("\<\%[^\@].*") and
  f.getLocation().getFile().getBaseName().matches(".*\.jsp$")
select l, "JSP scriptlet detected. Scriptlets are difficult to use securely and are considered bad practice. " +
  "See https://stackoverflow.com/a/3180202. Instead, consider migrating to JSF or using the Expression Language '${...}' " +
  "with the escapeXml function in your JSP files."