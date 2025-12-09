/**
 * @name Use of unescaped Expression Language in JSP
 * @description Detected an Expression Language segment that does not escape output.
 * @kind problem
 * @problem.severity warning
 * @id py/xss/unescaped-expression
 * @tags security
 *       jsp
 *       owasp:a3
 *       cwe:116
 */

import python
import semmle.python.web.Jsp
import semmle.python.dataflow.TaintTracking
import semmle.python.frameworks.JSTL

class UnescapedExpression extends Jsp::Expression {
  UnescapedExpression() {
    this.getText().regexMatches("\\$\\{(?!.*escapeXml).*\\}")
  }
}

class EscapeXmlCall extends JSTL::FunctionCall {
  EscapeXmlCall() {
    this.getPackageName() = "javax.servlet.jsp.jstl.core" and
    this.getClassName() = "Functions" and
    this.getMethodName() = "escapeXml"
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "XSS_JSTL_ESCAPE" }

  override predicate isSource(DataFlow::Node source) {
    exists(UnescapedExpression expr |
      source.asExpr() = expr
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Jsp::Expression expr |
      sink.asExpr() = expr and
      not exists(EscapeXmlCall escape |
        expr.getEnclosingCallable().getACallTo(escape) |
        expr.getText().regexMatches(".*escapeXml.*")
      )
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(EscapeXmlCall escape |
      sanitizer.asExpr() = escape
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, Config config
where config.hasFlowPath(source, sink)
select sink.getNode(), "Detected an Expression Language segment that does not escape output. " +
  "This is dangerous because if any data in this expression can be controlled externally, " +
  "it is a cross-site scripting vulnerability. Instead, use the 'escapeXml' function from the JSTL taglib."