/**
 * @name EL Expression Injection
 * @description An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @id java/el-injection
 * @severity Warning
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.internal.TaintTrackingImpl
import semmle.code.java.dataflow.internal.FlowSourcesImpl

class DynamicInputSource extends Parameter {
  DynamicInputSource() {
    exists(Method m | m = this.getAnAccessibleParameter() |
      not this.getType().toString() = "javax.el.Expression"
    )
  }
}

class ExpressionFactoryCall extends DataFlow::Node {
  ExpressionFactoryCall() {
    exists(Method ma |
      ma.getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
      (ma.getName() = "createValueExpression" or ma.getName() = "createMethodExpression") and
      this.asParameter() = ma.getParameter(1)
    )
  }
}

class ConstraintViolationCall extends DataFlow::Node {
  ConstraintViolationCall() {
    exists(Method ma |
      ma.getName() = "buildConstraintViolationWithTemplate" and
      this.asParameter() = ma.getParameter(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(StringLiteral sl | this.asParameter() = sl and sl.getValue() = "\"...\"")
  }
}

class ElInjectionConfig extends TaintTracking::Configuration {
  ElInjectionConfig() { this = "ElInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof DynamicInputSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ExpressionFactoryCall or sink instanceof ConstraintViolationCall
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof StringLiteralSanitizer
  }
}

from ElInjectionConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential EL expression injection from $@", source, "user input"