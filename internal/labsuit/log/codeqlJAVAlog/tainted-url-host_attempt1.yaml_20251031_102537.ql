/**
 * @name Tainted URL Host
 * @description User data flows into the host portion of this manually-constructed URL.
 *              This could allow an attacker to send data to their own server (SSRF).
 * @kind taint
 * @problem.severity ERROR
 * @id java/tainted-url-host
 * @tags security
 *       ssrf
 *       web-security
 *       cwe/918
 *       owasp-a10
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.spring.SpringController

class SSRFConfig extends TaintTracking::Configuration {
  SSRFConfig() { this = "SSRFConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodParameter p |
      source.asParameter() = p and
      p.getType().hasName("String") and
      not p.getType().getName().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)$") and
      (
        p.getAnAnnotation().getType().getName().matches("RequestBody") or
        p.getAnAnnotation().getType().getName().matches("PathVariable") or
        p.getAnAnnotation().getType().getName().matches("RequestParam") or
        p.getAnAnnotation().getType().getName().matches("RequestHeader") or
        p.getAnAnnotation().getType().getName().matches("CookieValue") or
        p.getAnAnnotation().getType().getName().matches("ModelAttribute")
      )
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
      ma.getMethod().hasName("concat") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      ma.getArgument(0) = arg and
      sink.asExpr() = arg
    )
    or
    // String format
    exists(MethodAccess ma, Expr arg |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      ma.getArgument(0) = arg and
      sink.asExpr() = arg
    )
    or
    // StringBuilder append
    exists(MethodAccess ma, Expr arg |
      ma.getMethod().hasName("append") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      ma.getReceiver().toString().matches("http(s?)://%(v|s|q).*") and
      ma.getArgument(0) = arg and
      sink.asExpr() = arg
    )
    or
    // String += assignment
    exists(AssignExpr ae, Expr rhs |
      ae.toString().matches("^\\$\\w+ \\+=.*") and
      ae.getType().getName().matches("http(s?)://%(v|s|q).*") and
      rhs = ae.getRightOperand() and
      sink.asExpr() = rhs
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getHost" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.net", "URL") and
      sanitizer.asExpr() = ma
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Parameterizable p, Parameter param, Expr arg |
      param = p.getAParameter() and
      param.getType().hasName("String") and
      arg = p.getArgument(param.getIndex()) and
      node1.asExpr() = arg and
      node2.asParameter() = param
    )
  }
}

from SSRFConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "User data flows into host portion of URL, possibly causing SSRF (Server-Side Request Forgery)", source,
  "User input from $@ flows into URL host construction here", source, "input parameter"