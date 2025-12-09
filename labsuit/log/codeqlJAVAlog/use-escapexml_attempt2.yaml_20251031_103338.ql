/**
 * @name Use of unescaped Expression Language output
 * @description Detected an Expression Language segment that does not escape output.
 *              This is dangerous because if any data in this expression can be controlled
 *              externally, it is a cross-site scripting vulnerability.
 * @kind problem
 * @problem.severity warning
 * @id java/use-escapexml
 * @tags security
 *       jsp
 * @precision high
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import semmle.code.java.security.XSS
import semmle.code.java.frameworks.JSTL

predicate isUnescapedELExpr(DataFlow::Expr expr) {
  exists(string value |
    value = expr.toString() and
    value.matches("\\$\\{(?!.*escapeXml).*\\}")
  )
}

class UnescapedExpression extends DataFlow::Expr {
  UnescapedExpression() { isUnescapedELExpr(this) }
}

class EscapeXMlCall extends DataFlow::MethodAccess {
  EscapeXMlCall() {
    this.getMethod().hasName("escapeXml") and
    this.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.jsp.jstl.core", "Functions")
  }
}

class XSSConfig extends TaintTracking::Configuration {
  XSSConfig() { this = "XSSConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(UnescapedExpression expr | source.asExpr() = expr)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(UnescapedExpression expr | sink.asExpr() = expr)
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(EscapeXMlCall escapeCall | sanitizer.asExpr() = escapeCall)
  }
}

from XSSConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), "Detected an Expression Language segment that does not escape output. " +
  "This is dangerous because if any data in this expression can be controlled externally, " +
  "it is a cross-site scripting vulnerability. Instead, use the 'escapeXml' function " +
  "from the JSTL taglib."