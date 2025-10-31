/**
 * @id no-scriptlets
 * @kind problem
 * @severity warning
 * @name JSP scriptlet detected
 * @description Scriptlets are difficult to use securely and are considered bad practice. Consider migrating to JSF or using the Expression Language '${...}' with the escapeXml function instead.
 * @tags security
 *       jsp
 *       injection
 */

import java
import semmle.code.java.StringUtil

from Literal scriptlet, CompilationUnit f
where
  regexpMatch(scriptlet.getValue(), "\\<\\%[^\\@].*") and
  regexpMatch(f.getFile().getBaseName(), ".*\\.jsp$")
select scriptlet, "JSP scriptlet detected. Consider replacing with Expression Language or migrating to JSF."