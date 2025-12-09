/**
 * @id el-injection
 * @severity WARNING
 * @kind taint
 * @message An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 */

import java
import DataFlow::PathGraph
import semmle.code.java.dataflow.TaintTracking

predicate isSource(DataFlow::Node source) {
  exists(Parameter p |
    source.asParameter() = p and
    p.getType().hasName("String") and
    not exists(p.getInitializer().getStringValue())
  )
}

predicate isSink(DataFlow::Node sink) {
  exists(Call c |
    (
      c.getMethod().getName() = "createValueExpression" or
      c.getMethod().getName() = "createMethodExpression" or
      c.getMethod().getName() = "buildConstraintViolationWithTemplate"
    ) and
    sink.asExpr() = c.getArgument(1)
  )
}

predicate isSanitizer(DataFlow::Node sanitizer) {
  exists(StringLiteral s |
    sanitizer.asExpr() = s and
    s.getStringValue() matches "\".*\""
  )
}

class ElInjectionConfig extends TaintTracking::Configuration {
  ElInjectionConfig() { this = "ElInjectionConfig" }
  override predicate isSource(DataFlow::Node source) { ::isSource(source) }
  override predicate isSink(DataFlow::Node sink) { ::isSink(sink) }
  override predicate isSanitizer(DataFlow::Node sanitizer) { ::isSanitizer(sanitizer) }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  any(ElInjectionConfig c).hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential EL injection from $@ to $@", source.getNode(),
  "user input", sink.getNode(), "expression evaluation"