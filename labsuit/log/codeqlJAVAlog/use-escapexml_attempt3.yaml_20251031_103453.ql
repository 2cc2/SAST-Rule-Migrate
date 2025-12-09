/**
 * @name Unescaped Expression Language in JSP
 * @description Detects Expression Language segments that don't escape output
 * @id use-escapexml
 * @kind path-problem
 * @severity warning
 * @tags security
 *       jsp
 * @problem.severity warning
 * @precision high
 * @security-severity 8.0
 * @cwe.id 116
 * @cwe.url http://cwe.mitre.org/data/definitions/116.html
 * @owasp A03:2021
 */

import java
import codeql.java.dataflow.TaintTracking
import codeql.java.StringFormat
import codeql.java.security.XSS
import codeql.java.frameworks.JSTL

class UnescapedElExpression extends DataFlow::Node {
  UnescapedElExpression() {
    this.asExpr().regexpMatches("\\$\\{(?!.*escapeXml).*\\}")
  }
}

class EscapeXmlCall extends DataFlow::Node {
  EscapeXmlCall() {
    exists(Method m | 
      m.getDeclaringType().hasQualifiedName("javax.servlet.jsp.jstl.core", "Functions") and
      m.hasName("escapeXml") and
      this.asExpr().(MethodAccess).getMethod() = m
    )
  }
}

class XSSConfig extends TaintTracking::Configuration {
  XSSConfig() { this = "XSS_Config" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UnescapedElExpression
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof UnescapedElExpression
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof EscapeXmlCall
  }
}

from XSSConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), 
  "Detected an Expression Language segment that does not escape output. " +
  "This is dangerous because if any data in this expression can be controlled " +
  "externally, it is a cross-site scripting vulnerability. Instead, use " +
  "the 'escapeXml' function from the JSTL taglib.",
  source.getNode(), "Unescaped user input here"