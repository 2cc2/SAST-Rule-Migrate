/** 
 * @name OGNL Injection
 * @description A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @id java/ognl-injection
 * @severity Warning
 * @tags security
 *       cwe/cwe-94
 *       owasp/a03
 */
import java
import DataFlow::PathGraph
import semmle.code.java.dataflow.TaintTracking

class OgnlInjectionConfig extends TaintTracking::Configuration {
  OgnlInjectionConfig() { this = "OgnlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      source.asParameter() = p and
      p.getValue().toString() != ""
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      m.getDeclaringType().getName().matches("OgnlReflectionProvider|ReflectionProvider|TextParseUtil|TextParser|OgnlTextParser|OgnlUtil|VelocityStrutsUtil|StrutsUtil|OgnlTool|ValueStack") and
      m.getName().matches("getGetMethod|getSetMethod|getField|setProperties|setProperty|getValue|setValue|translateVariables|translateVariablesCollection|shallBeIncluded|commaDelimitedStringToSet|evaluate|callMethod|compile|isTrue|findString|findValue|getText|makeSelectList|setParameter") and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(StringLiteral lit |
      sanitizer.asExpr() = lit and
      lit.getStringValue().regexpMatch("^.*$")
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, OgnlInjectionConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential OGNL injection from $@ to $@", source.getNode(), "user input", sink.getNode(), "OGNL evaluation"