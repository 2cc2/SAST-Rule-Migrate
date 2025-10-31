/**
 * @name OGNL Injection
 * @description A expression is built with a dynamic value. The source of the value(s) should be 
 * verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @problem.severity warning
 * @id java/ognl-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class OgnlConfig extends TaintTracking::Configuration {
  OgnlConfig() { this = "OGNL Injection" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      source.asParameter() = p and
      p.getValue() != ""
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      sink.asExpr() = ma.getArgument(0) and
      m.getDeclaringType().getASupertype*().hasQualifiedName("ognl", 
        ["OgnlReflectionProvider", "ReflectionProvider", "TextParseUtil", "TextParser", 
         "OgnlTextParser", "OgnlUtil", "VelocityStrutsUtil", "StrutsUtil", 
         "OgnlTool", "ValueStack"]) and
      m.hasName(["getGetMethod", "getSetMethod", "getField", "setProperties", "setProperty", 
                "getValue", "setValue", "translateVariables", "translateVariablesCollection", 
                "shallBeIncluded", "commaDelimitedStringToSet", "evaluate", "callMethod", 
                "compile", "isTrue", "findString", "findValue", "getText", "makeSelectList", 
                "setParameter"])
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(StringLiteral sl | 
      sanitizer.asExpr() = sl and
      sl.getValue().regexpMatch("^\"[^\"]*\"$")
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where any(OgnlConfig cfg).hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "A expression is built with a dynamic value. The source of the value(s) should be verified to avoid OGNL injection."