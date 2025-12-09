/**
 * @name JSP Scriptlet Detection
 * @description Detects JSP scriptlets which are considered bad practice
 * @kind problem
 * @problem.severity warning
 * @id security/no-scriptlets
 * @precision high
 * @tags security
 *       jsp
 *       injection
 */

import java
import java.util.regex.Pattern

from File f, string content
where
  content = f.getContents() and
  f.getAbsolutePath().matches(".*\\.jsp$") and
  Pattern.compile("<%[^@].*").matcher(content).find()
select f, "JSP scriptlet detected. Scriptlets are difficult to use securely and are considered bad practice. " +
       "See https://stackoverflow.com/a/3180202. Instead, consider migrating to JSF or using the Expression Language '${...}' " +
       "with the escapeXml function in your JSP files."