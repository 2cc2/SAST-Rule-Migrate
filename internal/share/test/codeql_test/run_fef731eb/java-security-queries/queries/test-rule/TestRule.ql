/**
 * @name Use EscapeXml
 * @description Detected an Expression Language segment that does not escape output.
 *              This is dangerous because if any data in this expression can be controlled
 *              externally, it is a cross-site scripting vulnerability. Instead, use 
 *              the 'escapeXml' function from the JSTL taglib.
 * @kind problem
 * @problem.severity warning
 * @id java/use-escapexml
 * @tags security
 *       owasp:a03
 *       cwe:116
 *       technology/jsp
 */

import java

from Expr expr, File f
where 
  // Match JSP expression language patterns ${...}
  expr.toString().regexpMatch("\\$\\{[^}]*\\}") and
  // Exclude those containing 'escapeXml'
  not expr.toString().regexpMatch(".*escapeXml.*") and
  f.getAbsolutePath().matches("%.jsp")
select expr, "Expression Language segment does not escape output. Use 'escapeXml' function from JSTL taglib to prevent XSS vulnerabilities."