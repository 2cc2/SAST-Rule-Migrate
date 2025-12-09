/**
 * @name OGNL Injection
 * @description A expression is built with a dynamic value. The source of the value(s) should be 
 *              verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind path-problem
 * @problem.severity warning
 * @id java/ognl-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
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
      (
        m.getDeclaringType().getQualifiedName() = "ognl.OgnlReflectionProvider" or
        m.getDeclaringType().getQualifiedName() = "ognl.ReflectionProvider" or
        m.getDeclaringType().getQualifiedName() = "ognl.TextParseUtil" or
        m.getDeclaringType().getQualifiedName() = "ognl.TextParser" or
        m.getDeclaringType().getQualifiedName() = "ognl.OgnlTextParser" or
        m.getDeclaringType().getQualifiedName() = "ognl.OgnlUtil" or
        m.getDeclaringType().getQualifiedName() = "ognl.ValueStack"
      ) and
      (
        m.getName() = "getValue" or
        m.getName() = "setValue" or
        m.getName() = "compile" or
        m.getName() = "evaluate"
      ) and
      ma.getArgument(0) = sink.asExpr()
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(string sl |
      sl = sanitizer.asExpr().getStringValue() and
      sl.matches("\".*\"")
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, OgnlInjectionConfig conf
where conf.hasFlowPath(source, sink)
select sink, "Potential OGNL injection vulnerability from $@.", source, source.toString()