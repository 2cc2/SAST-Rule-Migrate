/**
 * @name JSP Scriptlet Detected
 * @description Detects JSP scriptlets which are considered bad practice for security reasons.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.0
 * @id java/jsp-scriptlet
 * @tags security
 *       jsp
 *       injection
 */
import java
import semmle.code.java.dataflow.FlowSources

from Literal literal, File jspFile
where 
  // Source match: JSP scriptlet pattern
  literal.getValue().regexpMatch("<%[^@].*") and
  // Sink match: JSP file extension
  jspFile.getBaseName().regexpMatch(".*\\.jsp$") and
  // Ensure the literal belongs to the JSP file
  literal.getFile() = jspFile
select jspFile, "JSP scriptlet detected. Scriptlets are difficult to use securely and are considered bad practice. See https://stackoverflow.com/a/3180202. Instead, consider migrating to JSF or using the Expression Language '${...}' with the escapeXml function in your JSP files."