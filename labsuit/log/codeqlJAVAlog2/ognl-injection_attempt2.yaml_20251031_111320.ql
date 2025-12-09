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
import semmle.code.java.dataflow.DataFlow

class OgnlInjectionConfig extends TaintTracking::Configuration {
  OgnlInjectionConfig() { this = "OgnlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter param |
      source.asParameter() = param and
      param.getUnannotatedType().hasName("String") and
      param.getCallable().getNumberOfParameters() > 0
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess call, Method method |
      sink.asExpr() = call.getArgument(0) and
      call.getMethod() = method and
      method.getDeclaringType().getPackage().getName().matches("%ognl%") and
      method.getDeclaringType().getName().matches(
        "OgnlReflectionProvider|ReflectionProvider|TextParseUtil|TextParser|OgnlTextParser|OgnlUtil|" +
        "VelocityStrutsUtil|StrutsUtil|OgnlTool|ValueStack"
      ) and
      method.getName().matches(
        "getGetMethod|getSetMethod|getField|setProperties|setProperty|getValue|setValue|" +
        "translateVariables|translateVariablesCollection|shallBeIncluded|commaDelimitedStringToSet|" +
        "evaluate|callMethod|compile|isTrue|findString|findValue|getText|makeSelectList|setParameter"
      )
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(stringLiteral |
      node.asExpr() = stringLiteral and
      stringLiteral instanceof Literal and
      stringLiteral.getType() instanceof StringType
    )
  }
}

from OgnlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, "Potential OGNL injection vulnerability due to use of dynamic value in code evaluation."