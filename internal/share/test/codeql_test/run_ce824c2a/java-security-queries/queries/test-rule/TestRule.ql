/**
 * @name EL Injection
 * @description Detects improper control of code generation (Expression Language injection).
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id java/el-injection
 * @tags security
 *       external/cwe/cwe-094
 *       owasp-a3
 *       cwe2022-top25
 */

import java
import semmle.code.java.dataflow.TaintTracking

class ELInjection extends TaintTracking::Configuration {
  ELInjection() { this = "ELInjection" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m, Parameter p |
      m.getAParameter() = p and
      p.getType().getName() = "String" and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      (mc.getMethod().getName() = "createValueExpression" or
       mc.getMethod().getName() = "createMethodExpression") and
      mc.getMethod().getDeclaringType().getName() = "ExpressionFactory" and
      sink.asExpr() = mc.getArgument(1)
    ) or
    exists(MethodCall mc |
      mc.getMethod().getName() = "buildConstraintViolationWithTemplate" and
      sink.asExpr() = mc.getArgument(0)
    )
  }
}

from DataFlow::Node source, DataFlow::Node sink, ELInjection conf
where conf.hasFlow(source, sink)
select sink, "An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."