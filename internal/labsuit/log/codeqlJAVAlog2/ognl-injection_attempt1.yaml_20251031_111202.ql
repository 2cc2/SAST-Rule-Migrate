/**
 * @name OGNL Injection
 * @description A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id java/ognl-injection
 * @tags security
 *       cwe/CWE-94
 *       owasp/a03
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

class OgnlInjectionConfig extends TaintTracking::Configuration {
  OgnlInjectionConfig() { this = "OgnlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodParameter param |
      source.asParameter() = param and
      param.getValue().toString() != ""
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess call, Method method |
      call.getMethod() = method and
      method.getDeclaringType().getPackage().getName().matches("ognl") and
      method.getDeclaringType().getName().matches(
        "OgnlReflectionProvider|ReflectionProvider|TextParseUtil|TextParser|OgnlTextParser|OgnlUtil|" +
        "VelocityStrutsUtil|StrutsUtil|OgnlTool|ValueStack"
      ) and
      method.getName().matches(
        "getGetMethod|getSetMethod|getField|setProperties|setProperty|getValue|setValue|" +
        "translateVariables|translateVariablesCollection|shallBeIncluded|commaDelimitedStringToSet|" +
        "evaluate|callMethod|compile|isTrue|findString|findValue|getText|makeSelectList|setParameter"
      ) and
      sink.asExpr() = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(Literal literal |
      node.asExpr() = literal and
      literal instanceof StringLiteral
    )
  }
}

from OgnlInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential OGNL injection vulnerability due to use of dynamic value in code evaluation."