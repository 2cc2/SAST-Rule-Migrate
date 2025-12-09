/**
 * @name Tainted URL host construction
 * @description User data flows into the host portion of manually-constructed URLs
 * @kind path-problem
 * @problem.severity error
 * @id java/tainted-url-host
 * @security-severity 8.8
 * @tags security
 *       external/cwe/cwe-918
 *       external/owasp/a10
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.spring.SpringController

class SSRFConfig extends TaintTracking::Configuration {
  SSRFConfig() { this = "SSRF" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodParameter p |
      source.asParameter() = p and
      p.getType().hasName("java.lang.String") and
      p.getAnnotatedType().getAnnotation().getType().getName().matches("%(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)%") and
      not p.getType().getName().matches("%(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)%")
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // URL construction
    exists(ConstructorCall cc, Expr arg |
      cc.getConstructedType().hasQualifiedName("java.net", "URL") and
      cc.getArgument(0) = arg and
      sink.asExpr() = arg
    )
    or
    // String concatenation
    exists(MethodAccess ma, Expr arg |
      ma.getMethod().getName().matches("concat|format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      ma.getArgument(0) = arg and
      sink.asExpr() = arg
    )
    or
    // StringBuilder append
    exists(MethodAccess ma, Expr arg |
      ma.getMethod().getName() = "append" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      ma.getQualifier().toString().matches("http(s?)://%(v|s|q).*") and
      ma.getArgument(0) = arg and
      sink.asExpr() = arg
    )
    or
    // String += operator
    exists(AssignExpr assign, Expr rhs |
      assign.getOperator().toString() = "+=" and
      assign.getRhs() = rhs and
      rhs.getType().hasName("java.lang.String") and
      assign.toString().matches("^\\$\\w+ \\+=.*") and
      rhs.toString().matches("http(s?)://%(v|s|q).*") and
      sink.asExpr() = rhs
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getHost" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.net", "URL") and
      sanitizer.asExpr() = ma.getQualifier()
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Parameterizable p, Parameter param, Expr arg |
      pred.asParameter() = param and
      succ.asExpr() = arg and
      param.getType().hasName("java.lang.String") and
      arg.getType().hasName("java.lang.String")
    )
  }
}

from SSRFConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "User data flows into the host portion of this manually-constructed URL. This could allow SSRF."