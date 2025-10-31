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
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

class DynamicInputSource extends TaintTracking::Source {
  DynamicInputSource() {
    exists(Method m, Parameter p |
      m = p.getMethod() and
      not p.getType().hasName("javax.el.Expression") and
      this.asParameter() = p
    )
  }
}

class ExpressionFactorySink extends TaintTracking::Sink {
  ExpressionFactorySink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
      (ma.getMethod().getName() = "createValueExpression" or
       ma.getMethod().getName() = "createMethodExpression") and
      this.asExpr() = ma.getArgument(1)
    )
  }
}

class ConstraintViolationSink extends TaintTracking::Sink {
  ConstraintViolationSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "buildConstraintViolationWithTemplate" and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends TaintTracking::Sanitizer {
  StringLiteralSanitizer() {
    exists(StringLiteral sl | this.asExpr() = sl and sl.getStringValue() = "...")
  }
}

from DynamicInputSource source, TaintTracking::Sink sink
where sink instanceof ExpressionFactorySink or sink instanceof ConstraintViolationSink and
      TaintTracking::localTaint(DataFlow::parameterNode(source), DataFlow::exprNode(sink))
select sink, "Potential EL expression injection from $@", source, "user input"