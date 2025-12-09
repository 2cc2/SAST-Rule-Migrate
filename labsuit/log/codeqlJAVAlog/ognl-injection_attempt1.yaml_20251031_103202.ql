/**
 * @name OGNL Injection
 * @description A expression is built with a dynamic value. The source of the value(s) should be 
 *              verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind path-problem
 * @problem.severity Warning
 * @security-severity 7.5
 * @precision high
 * @id java/ognl-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class OgnlInjectionConfig extends TaintTracking::Configuration {
  OgnlInjectionConfig() { this = "OgnlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodParameter p | 
      source.asParameter() = p and
      p.getValueText() != ""
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      m.getDeclaringType().getPackage().getName().matches("ognl%") and
      m.getDeclaringType().getName() in [
        "OgnlReflectionProvider", "ReflectionProvider", "TextParseUtil", "TextParser", 
        "OgnlTextParser", "OgnlUtil", "VelocityStrutsUtil", "StrutsUtil", 
        "OgnlTool", "ValueStack"
      ] and
      m.getName() in [
        "getGetMethod", "getSetMethod", "getField", "setProperties", "setProperty", 
        "getValue", "setValue", "translateVariables", "translateVariablesCollection", 
        "shallBeIncluded", "commaDelimitedStringToSet", "evaluate", "callMethod", 
        "compile", "isTrue", "findString", "findValue", "getText", "makeSelectList", 
        "setParameter"
      ] and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(StringLiteral lit | 
      node.asExpr() = lit and 
      lit.getStringValue().regexpMatch("^".*"$")
    )
  }
}

from OgnlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "The expression is built with a dynamic value that may lead to OGNL injection."