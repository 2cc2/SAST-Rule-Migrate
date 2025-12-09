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
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

predicate isUnescapedExpression(DataFlow::Node node) {
  exists(Expr e |
    node.asExpr() = e and
    e.toString().matches("\\$\\{(?!.*escapeXml).*\\}")
  )
}

predicate isXSSSink(DataFlow::Node node) {
  exists(MethodAccess ma |
    node.asExpr() = ma and
    ma.toString().matches("\\$\\{(?!.*escapeXml).*\\}")
  )
}

predicate isEscapeXmlCall(DataFlow::Node node) {
  exists(MethodAccess ma |
    node.asExpr() = ma and
    ma.getMethod().hasName("escapeXml") and
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.jsp.jstl.core", "Functions")
  )
}

class UnescapedExpressionConfig extends TaintTracking::Configuration {
  UnescapedExpressionConfig() { this = "UnescapedExpressionConfig" }

  override predicate isSource(DataFlow::Node source) {
    isUnescapedExpression(source)
  }

  override predicate isSink(DataFlow::Node sink) {
    isXSSSink(sink)
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    isEscapeXmlCall(sanitizer)
  }
}

from DataFlow::Node source, DataFlow::Node sink
where 
  any(UnescapedExpressionConfig config).hasFlow(source, sink)
select sink, "Detected an Expression Language segment that does not escape output. " +
  "This could lead to XSS vulnerabilities. Use 'escapeXml' function from JSTL taglib instead."