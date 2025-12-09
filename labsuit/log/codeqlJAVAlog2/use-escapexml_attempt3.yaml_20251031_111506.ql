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
import dataflow
import dataflow.paths
import jsp

predicate isUnescapedExpression(Expr e) {
  e.toString().matches("\\$\\{(?!.*escapeXml).*\\}")
}

predicate isXSSSink(MethodAccess ma) {
  ma.toString().matches("\\$\\{(?!.*escapeXml).*\\}")
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
  dataflow::localFlow(dataflow::exprNode(source), dataflow::exprNode(sink)) and
  not exists(EscapeXMLSanitizer sanitizer |
    dataflow::localFlow(dataflow::exprNode(source), dataflow::exprNode(sanitizer)) and
    dataflow::localFlow(dataflow::exprNode(sanitizer), dataflow::exprNode(sink))
  )
select sink, "Detected an Expression Language segment that does not escape output. " +
  "This could lead to XSS vulnerabilities. Use 'escapeXml' function from JSTL taglib instead."