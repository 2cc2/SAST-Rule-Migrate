/**
 * @name Expression Language Injection
 * @description An expression is built with a dynamic value. The source of the value(s) should 
 * be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @id java/el-injection
 * @severity Warning
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class DynamicInputSource extends DataFlow::Node {
  DynamicInputSource() {
    exists(MethodParameter p |
      this.asParameter() = p and
      not p.getInitializer().(StringLiteral).getValue() = "..."
    )
  }
}

class ExpressionSink extends DataFlow::Node {
  ExpressionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "createValueExpression" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
      this.asExpr() = ma.getArgument(1)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().getName() = "createMethodExpression" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
      this.asExpr() = ma.getArgument(1)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().getName() = "buildConstraintViolationWithTemplate" and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(StringLiteral sl | sl.getValue() = "..." and this.asExpr() = sl)
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