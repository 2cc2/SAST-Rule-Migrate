/**
 * @name Tainted URL Host
 * @description User data flows into the host portion of this manually-constructed URL. This could allow an attacker 
 * to send data to their own server, potentially exposing sensitive data such as cookies or authorization 
 * information sent with this request. They could also probe internal servers or other resources that the server 
 * running this code can access. (This is called server-side request forgery, or SSRF.) Do not allow arbitrary 
 * hosts. Instead, create an allowlist for approved hosts, hardcode the correct host, or ensure that the user 
 * data can only affect the path or parameters.
 * @kind problem
 * @id java/ssrf
 * @tags security
 *       external/cwe/cwe-918
 *       external/owasp/a10
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.frameworks.HttpRequest
import semmle.code.java.StringFormat

class UserInputSource extends DataFlow::Source {
  UserInputSource() {
    exists(Parameter p |
      p = this.asParameter() and
      p.getType().hasName("String") and
      exists(Annotation a |
        a = p.getAnAnnotation() and
        a.getType().getName().regexpMatch("(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)")
      ) and
      not p.getType().getName().regexpMatch("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)$")
    )
  }
}

class UrlConstructionSink extends DataFlow::Node {
  UrlConstructionSink() {
    exists(MethodCall mc |
      mc = this.asExpr() and
      mc.getMethod().getName() = "<init>" and
      mc.getMethod().getDeclaringType().hasName("URL") and
      exists(Method m | 
        m = mc.getMethod() and 
        m.getNumberOfParameters() = 1 and 
        m.getParameter(0).getType().hasName("String")
      )
    )
  }
}

class StringConcatSink extends DataFlow::Node {
  StringConcatSink() {
    exists(MethodCall mc |
      mc = this.asExpr() and
      (mc.getMethod().getName() = "concat" or mc.getMethod().getName() = "format") and
      mc.getMethod().getDeclaringType().hasName("String")
    )
  }
}

class StringBuilderAppendSink extends DataFlow::Node {
  StringBuilderAppendSink() {
    exists(MethodCall mc |
      mc = this.asExpr() and
      mc.getMethod().getName() = "append" and
      mc.getMethod().getDeclaringType().hasName("StringBuilder") and
      exists(Expr receiver |
        receiver = mc.getReceiver() and
        receiver.toString().regexpMatch("http(s?)://%(v|s|q).*")
      )
    )
  }
}

class StringPlusAssignSink extends DataFlow::Node {
  StringPlusAssignSink() {
    exists(AssignExpr ae |
      ae = this.asExpr() and
      ae.getOpKind() = ADD_ASSIGN and
      ae.getLeftOperand().getType().hasName("String") and
      ae.getLeftOperand().toString().regexpMatch("^(\\\\$\\\\w+) \\\\+=.*")
    )
  }
}

class UrlValidationSanitizer extends DataFlow::Barrier {
  UrlValidationSanitizer() {
    exists(MethodCall mc |
      mc = this.asExpr() and
      mc.getMethod().getName() = "getHost" and
      mc.getMethod().getDeclaringType().hasName("URL")
    )
  }
}

class TaintedUrlHostConfig extends DataFlow::Configuration {
  TaintedUrlHostConfig() { this = "Tainted URL Host Configuration" }

  override predicate isSource(DataFlow::Node source) { source instanceof UserInputSource }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof UrlConstructionSink or
    sink instanceof StringConcatSink or
    sink instanceof StringBuilderAppendSink or
    sink instanceof StringPlusAssignSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof UrlValidationSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    pred.getType() instanceof TypeString and succ.getType() instanceof TypeString
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedUrlHostConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source.getNode(), 
  "User-provided data flows into URL host construction, potentially enabling SSRF (Server-Side Request Forgery)"