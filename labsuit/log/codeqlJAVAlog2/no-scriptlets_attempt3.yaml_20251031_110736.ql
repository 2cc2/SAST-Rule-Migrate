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

from string scriptContent, string filePath
where
  // Match JSP scriptlet pattern
  regex.matches(scriptContent, "<%[^@].*") and
  // Match JSP file extension
  regex.matches(filePath, ".*\\.jsp$")
select scriptContent, "JSP scriptlet detected in file. Scriptlets are difficult to use securely and are considered bad practice. " +
       "See https://stackoverflow.com/a/3180202. Instead, consider migrating to JSF or using the Expression Language '${...}' " +
       "with the escapeXml function in your JSP files.",
  scriptContent, "File: " + filePath