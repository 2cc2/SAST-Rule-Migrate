/**
 * @name EL表达式注入
 * @description 检测动态值构建的EL表达式，可能造成代码注入漏洞
 * @kind problem
 * @id java/el-injection
 * @severity warning
 * @tags security
 *       cwe/cwe-94
 *       owasp/a03
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class ElInjectionConfig extends TaintTracking::Configuration {
  ElInjectionConfig() { this = "ElInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      source.asParameter() = p and
      p.getType().hasName("String") and
      p.getName().regexpMatch("[^\\\"].*")
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      (
        ma.getMethod().getName() = "createValueExpression" and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
        sink.asExpr() = ma.getArgument(1)
      )
      or
      (
        ma.getMethod().getName() = "createMethodExpression" and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
        sink.asExpr() = ma.getArgument(1)
      )
      or
      (
        ma.getMethod().getName() = "buildConstraintViolationWithTemplate" and
        sink.asExpr() = ma.getArgument(0)
      )
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Literal lit |
      sanitizer.asExpr() = lit and
      lit.getStringValue().regexpMatch("\".*\"")
    )
  }
}

from DataFlow::Node source, DataFlow::Node sink
where
  any(ElInjectionConfig c).hasFlow(source, sink)
select sink, "An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."