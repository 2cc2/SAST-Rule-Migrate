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

import semmle.code.java.DataFlow
import semmle.code.java.frameworks.JSTL
import semmle.code.java.dataflow.TaintTracking

predicate isUnescapedExpression(Expression e) {
  e.toString().matches("\\$\\{(?!.*escapeXml).*\\}")
}

predicate isXSSSink(MethodAccess ma) {
  ma.toString().matches("\\$\\{(?!.*escapeXml).*\\}")
}

predicate isEscapeXmlCall(MethodAccess ma) {
  ma.getMethod().hasName("escapeXml") and
  ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.jsp.jstl.core", "Functions")
}

class UnescapedExpressionSource extends Expression {
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