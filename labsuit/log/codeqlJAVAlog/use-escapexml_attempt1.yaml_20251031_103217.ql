/**
 * @name Use of unescaped Expression Language
 * @description Detected an Expression Language segment that does not escape output.
 *              This is dangerous because if any data in this expression can be controlled
 *              externally, it is a cross-site scripting vulnerability. Instead, use
 *              the 'escapeXml' function from the JSTL taglib.
 * @kind problem
 * @id java/use-escapexml
 * @severity Warning
 * @tags security
 *       jsp
 * @security-severity 8.0
 * @precision high
 * @problem.severity error
 */

import java
import semmle.code.java.StringFormat
import semmle.code.java.security.XSS
import semmle.code.java.frameworks.JSTL

predicate isUnescapedELExpr(Expr expr) {
  exists(MethodAccess ma |
    ma.getMethod().getName() = "getParameter" and
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest") and
    expr.toString().matches("\\$\\{(?!.*escapeXml).*\\}")
  )
}

predicate isXSSSink(Expr expr) {
  expr.toString().matches("\\$\\{(?!.*escapeXml).*\\}")
}

predicate isEscapeXmlCall(Expr expr) {
  exists(MethodAccess ma |
    ma.getMethod().getName() = "escapeXml" and
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.jsp.jstl.core", "Functions")
  )
}

from Expr source, Expr sink, MethodAccess escapeCall
where
  isUnescapedELExpr(source) and
  isXSSSink(sink) and
  source.flowsTo(sink) and
  not exists(escapeCall |
    isEscapeXmlCall(escapeCall) and
    escapeCall.getAnArgument() = source
  )
select sink, "Detected an Expression Language segment that does not escape output. " +
       "This could lead to cross-site scripting vulnerability. " +
       "Use 'escapeXml' function from JSTL taglib instead."