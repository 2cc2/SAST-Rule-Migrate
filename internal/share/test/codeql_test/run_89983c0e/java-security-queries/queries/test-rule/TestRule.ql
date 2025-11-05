/**
 * @id no-scriptlets
 * @kind problem
 * @severity Warning
 * @name JSP scriptlet detected
 * @description JSP scriptlet detected. Scriptlets are difficult to use securely and are considered bad practice. See https://stackoverflow.com/a/3180202. Instead, consider migrating to JSF or using the Expression Language '${...}' with the escapeXml function in your JSP files.
 * @tags security
 *       jsp
 *       injection
 */

import java

from Literal literal, File file
where regexpMatch(literal.getValue(), "\\<\\%[^\\@].*") and
      regexpMatch(file.getBaseName(), ".*\\.jsp$") and
      literal.getFile() = file
select literal, "JSP scriptlet detected. Avoid using scriptlets as they can lead to security issues."