/**
 * @name JSP Scriptlet Detection
 * @description Detects JSP scriptlets which are considered bad practice.
 * @kind problem
 * @problem.severity warning
 * @id security/no-scriptlets
 * @tags security
 *       jsp
 *       injection
 */

import java
import regex

from Literal literal, File file
where
  // Match JSP scriptlet pattern
  regex.match(/<\%[^\@].*/, literal.getValue().toString()) and
  // Match JSP file extension
  regex.match(/.*\.jsp$/, file.getBaseName())
select file, "JSP scriptlet detected in $@. Scriptlets are difficult to use securely and are considered bad practice. "
       + "See https://stackoverflow.com/a/3180202. Instead, consider migrating to JSF or using the Expression Language '${...}' "
       + "with the escapeXml function in your JSP files.",
  file, file.getBaseName()