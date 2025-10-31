/**
 * @name Tainted URL host
 * @description User data flows into the host portion of this manually-constructed URL. This could allow an attacker to send data to their own server, potentially exposing sensitive data such as cookies or authorization information sent with this request. They could also probe internal servers or other resources that the server running this code can access. (This is called server-side request forgery, or SSRF.) Do not allow arbitrary hosts. Instead, create an allowlist for approved hosts, or hardcode the correct host.
 * @kind taint
 * @problem.severity warning
 * @id py/tainted-url-host
 * @tags security
 *       cwe: "CWE-918: Server-Side Request Forgery (SSRF)"
 *       owasp: "A10:2021 - Server-Side Request Forgery (SSRF)"
 */

import python
import semmle.python.security.Xss
import DataFlow::PathGraph

class FlaskRequestSource extends DataFlow::Node {
  FlaskRequestSource() {
    exists(MethodAccess ma |
      ma.getMethod().getQualifiedName().matches("flask.request.%") and
      ma.getAnArg() = this.asExpr()
    )
  }
}

class RouteParamSource extends DataFlow::Node {
  RouteParamSource() {
    exists(FunctionDef fd, Parameter p |
      fd.getDecoratorCall("route").exists() and
      p = fd.getAParameter() and
      p.getName().matches("^\\$ROUTEVAR$") and
      this.asParameter() = p
    )
  }
}

class PercentConstructedUrlSink extends DataFlow::Node {
  PercentConstructedUrlSink() {
    exists(StringFormatExpr sfe |
      sfe.getText().regexpMatch("\".*\" % .*") and
      sfe.getText().regexpMatch(".*://%s|.*://%r") and
      this.asExpr() = sfe
    )
  }
}

class FormatConstructedUrlSink extends DataFlow::Node {
  FormatConstructedUrlSink() {
    exists(MethodCall mc |
      mc.getMethod().getName() = "format" and
      mc.getQualifier().getText().regexpMatch("\".*\"") and
      mc.getQualifier().getText().regexpMatch(".*://\\s*\\{.*\\}") and
      this.asExpr() = mc
    )
  }
}

class ConcatConstructedUrlSink extends DataFlow::Node {
  ConcatConstructedUrlSink() {
    exists(BinaryExpr be |
      be.getOperator() = "+" and
      be.getLeft().getText().regexpMatch("\".*\"") and
      be.getLeft().getText().regexpMatch(".*://$") and
      this.asExpr() = be
    )
  }
}

class FStringConstructedUrlSink extends DataFlow::Node {
  FStringConstructedUrlSink() {
    exists(InterpolatedStringExpr ise |
      ise.getText().regexpMatch("f\".*\\{.*\\}.*\"") and
      ise.getText().regexpMatch(".*://$") and
      this.asExpr() = ise
    )
  }
}

class InplaceConstructedUrlSink extends DataFlow::Node {
  InplaceConstructedUrlSink() {
    exists(BinaryExpr be |
      be.getOperator() = "+=" and
      be.getLeft() instanceof Name and
      ((Name)be.getLeft()).getId().getText().matches("\$URL") and
      be.getRight().getText().matches("\$URLSTR") and
      be.getText().regexpMatch(".*://$") and
      this.asExpr() = be
    )
  }
}

predicate isSource(DataFlow::Node source) {
  source instanceof FlaskRequestSource or
  source instanceof RouteParamSource
}

predicate isSink(DataFlow::Node sink) {
  sink instanceof PercentConstructedUrlSink or
  sink instanceof FormatConstructedUrlSink or
  sink instanceof ConcatConstructedUrlSink or
  sink instanceof FStringConstructedUrlSink or
  sink instanceof InplaceConstructedUrlSink
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  isSource(source.getNode()) and
  isSink(sink.getNode()) and
  DataFlow::flowPath(source, sink)
select sink.getNode(), "User data flows into the host portion of this manually-constructed URL, which could lead to SSRF vulnerability."