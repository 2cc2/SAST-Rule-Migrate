/**
 * @name Use of unescaped Expression Language
 * @description Detected an Expression Language segment that does not escape output.
 * @kind problem
 * @id jsp/use-escapexml
 * @tags security
 *       jsp
 *       external/cwe/cwe-116
 * @severity warning
 */

import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import semmle.code.java.security.XSS
import semmle.code.java.frameworks.JSTL

class UnescapedElExpression extends Expr {
  UnescapedElExpression() {
    this instanceof StringLiteral and
    this.getText().matches("\\$\\{(?!.*escapeXml).*\\}")
  }
}

class EscapeXmlCall extends DataFlow::Node {
  EscapeXmlCall() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.jsp.jstl.core", "Functions") and
      ma.getMethod().hasName("escapeXml") and
      this.asExpr() = ma
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "UseEscapedXmlConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(UnescapedElExpression el |
      source.asExpr() = el
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(UnescapedElExpression el |
      sink.asExpr() = el
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(EscapeXmlCall call |
      sanitizer = call
    )
  }
}

from Config config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), 
  "Detected an Expression Language segment that does not escape output. This is dangerous because if any data in this expression can be controlled externally, it is a cross-site scripting vulnerability. Instead, use the 'escapeXml' function from the JSTL taglib."