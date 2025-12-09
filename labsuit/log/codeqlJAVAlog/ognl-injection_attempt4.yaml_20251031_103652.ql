/**
 * @name OGNL Injection
 * @description A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind path-problem
 * @problem.severity warning
 * @id java/ognl-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03:2021
 */

import java
import DataFlow::PathGraph
import semmle.code.java.dataflow.TaintTracking

class OgnlConfig extends TaintTracking::Config {
  OgnlConfig() { this = "OgnlConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(ParameterNode p |
      source.asParameterNode() = p and
      source.asParameterNode().getType().toString() != "" and
      source.asParameterNode().getType().toString() != "null"
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccessNode ma |
      ma.getMethod().getDeclaringType().getName().matches("OgnlReflectionProvider|ReflectionProvider|TextParseUtil|TextParser|OgnlTextParser|OgnlUtil|VelocityStrutsUtil|StrutsUtil|OgnlTool|ValueStack") and
      ma.getMethod().getName().matches("getGetMethod|getSetMethod|getField|setProperties|setProperty|getValue|setValue|translateVariables|translateVariablesCollection|shallBeIncluded|commaDelimitedStringToSet|evaluate|callMethod|compile|isTrue|findString|findValue|getText|makeSelectList|setParameter") and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(StringLiteralNode sl |
      sanitizer.asExpr() = sl and
      sl.getStringValue().matches("^\".*\"$")
    )
  }
}

from OgnlConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Potential OGNL injection from $@ to $@.", source.getNode(), sink.getNode(), "User input"