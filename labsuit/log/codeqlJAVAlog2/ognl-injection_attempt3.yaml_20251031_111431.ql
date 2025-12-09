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
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.OGNL

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
        m.getDeclaringType().getASourceSupertype*().getName() = "OgnlReflectionProvider" or
        m.getDeclaringType().getASourceSupertype*().getName() = "ReflectionProvider" or
        // ... other OGNL related types
        m.getName() = "getValue" or
        m.getName() = "setValue" or
        // ... other OGNL related methods
        ma.getArgument(0) = sink.asExpr()
      )
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Literal lit |
      lit = sanitizer.asExpr() and
      lit.isStringLiteral()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, OgnlInjectionConfig conf
where conf.hasFlowPath(source, sink)
select sink, "Potential OGNL injection vulnerability from $@.", source, source.toString()