/**
 * @name Use EscapeXML in JSP
 * @description Detected an Expression Language segment that does not escape output. This is dangerous because if any data in this expression can be controlled externally, it is a cross-site scripting vulnerability. Instead, use the 'escapeXml' function from the JSTL taglib.
 * @kind path-problem
 * @problem.severity warning
 * @id jsp/use-escapexml
 * @tags security
 *       jsp
 * @precision high
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

predicate isUnescapedExpression(DataFlow::Node node) {
  exists(string expr |
    expr = node.asExpr().toString() and
    regexpMatch("\\$\\{(?!.*escapeXml).*\\}", expr)
  )
}

predicate isXSSSink(DataFlow::Node node) {
  exists(string expr |
    expr = node.asExpr().toString() and
    regexpMatch("\\$\\{(?!.*escapeXml).*\\}", expr)
  )
}

predicate isEscapeXmlCall(DataFlow::Node node) {
  exists(MethodCall mc |
    mc = node.asExpr() and
    mc.getFuncName() = "escapeXml" and
    mc.getModuleName() = "javax.servlet.jsp.jstl.core.Functions"
  )
}

class UnescapedExpressionConfig extends TaintTracking::Configuration {
  UnescapedExpressionConfig() { this = "UnescapedExpressionConfig_JSP" }

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

from DataFlow::Node source, DataFlow::Node sink, UnescapedExpressionConfig config
where 
  config.hasFlow(source, sink)
select sink, "Detected an Expression Language segment that does not escape output. " +
  "This could lead to XSS vulnerabilities. Use 'escapeXml' function from JSTL taglib instead."