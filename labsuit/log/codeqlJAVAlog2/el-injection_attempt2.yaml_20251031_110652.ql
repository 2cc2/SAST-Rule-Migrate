/**
 * @name Expression Language Injection
 * @description An expression is built with a dynamic value. The source of the value(s) should 
 * be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @id python/el-injection
 * @severity Warning
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */

import python
import semmle.code.python.dataflow.DataFlow
import semmle.code.python.dataflow.TaintTracking

class DynamicInputSource extends DataFlow::Node {
  DynamicInputSource() {
    exists(Parameter p |
      this.asParameter() = p and
      not p.getDefault().(Str).getValue() = "..."
    )
  }
}

class ExpressionSink extends DataFlow::Node {
  ExpressionSink() {
    exists(Call ma |
      ma.getFunc().getName() = "createValueExpression" and
      ma.getFunc().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
      this.asExpr() = ma.getArgument(1)
    )
    or
    exists(Call ma |
      ma.getFunc().getName() = "createMethodExpression" and
      ma.getFunc().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
      this.asExpr() = ma.getArgument(1)
    )
    or
    exists(Call ma |
      ma.getFunc().getName() = "buildConstraintViolationWithTemplate" and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(Str sl | sl.getValue() = "..." and this.asExpr() = sl)
  }
}

class ElInjectionConfig extends TaintTracking::Configuration {
  ElInjectionConfig() { this = "ElInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof DynamicInputSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ExpressionSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof StringLiteralSanitizer
  }
}

from ElInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential expression language injection from $@", source, source.toString()