/**
 * @name Use EscapeXML
 * @description Detected an Expression Language segment that does not escape output. This is dangerous because if any data in this expression can be controlled externally, it is a cross-site scripting vulnerability. Instead, use the 'escapeXml' function from the JSTL taglib.
 * @kind problem
 * @problem.severity warning
 * @id jsp/use-escapexml
 * @tags security
 *       jsp
 * @precision high
 */

import java
import regex

predicate isUnescapedExpression(Expr e) {
  exists(regex::Regex r |
    r.matches("\\$\\{(?!.*escapeXml).*\\}", e.toString())
  )
}

predicate isXSSSink(MethodAccess ma) {
  exists(regex::Regex r |
    r.matches("\\$\\{(?!.*escapeXml).*\\}", ma.toString())
  )
}

predicate isEscapeXmlCall(MethodAccess ma) {
  ma.getMethod().hasName("escapeXml") and
  ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.jsp.jstl.core", "Functions")
}

class UnescapedExpressionSource extends Expr {
  UnescapedExpressionSource() {
    isUnescapedExpression(this)
  }
}

class XSSSink extends MethodAccess {
  XSSSink() {
    isXSSSink(this)
  }
}

class EscapeXMLSanitizer extends MethodAccess {
  EscapeXMLSanitizer() {
    isEscapeXmlCall(this)
  }
}

from UnescapedExpressionSource source, XSSSink sink
where 
  DataFlow::localFlow(DataFlow::exprNode(source), DataFlow::exprNode(sink)) and
  not exists(EscapeXMLSanitizer sanitizer |
    DataFlow::localFlow(DataFlow::exprNode(source), DataFlow::exprNode(sanitizer)) and
    DataFlow::localFlow(DataFlow::exprNode(sanitizer), DataFlow::exprNode(sink))
  )
select sink, "Detected an Expression Language segment that does not escape output. " +
  "This could lead to XSS vulnerabilities. Use 'escapeXml' function from JSTL taglib instead."