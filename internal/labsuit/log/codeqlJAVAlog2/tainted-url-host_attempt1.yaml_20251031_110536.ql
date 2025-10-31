/** 
 * @name Tainted URL Host
 * @description User data flows into the host portion of this manually-constructed URL.
 * @kind problem
 * @id java/tainted-url-host
 * @tags security
 *       external/cwe/cwe-918
 *       external/owasp/a10
 *       ssrf
 *       web-security
 */
import java
 
// Source definitions
predicate isSource(DataFlow::Node source) {
  exists(Method m, Parameter p |
    source.asParameter() = p and
    p.getType().hasName("java.lang.String") and
    not p.getType().hasName(["Integer", "Long", "Float", "Double", "Char", "Boolean",
                           "int", "long", "float", "double", "char", "boolean"]) and
    (
      p.getAnAnnotation().getType().getName().matches("%(RequestBody|PathVariable|RequestParam|" +
                                                     "RequestHeader|CookieValue|ModelAttribute)%")
    )
  )
}
 
// Sink definitions
predicate isUrlConstructionSink(DataFlow::Node sink) {
  exists(ConstructorCall cc |
    cc.getConstructedType().hasQualifiedName("java.net", "URL") and
    cc.getArgument(0) = sink.asExpr()
  )
}
 
predicate isStringConcatSink(DataFlow::Node sink) {
  exists(MethodAccess ma |
    (ma.getMethod().getName() = "concat" and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")) or
    (ma.getMethod().getName() = "format" and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")) and
    ma.getArgument(0) = sink.asExpr()
  )
}
 
predicate isStringBuilderAppendSink(DataFlow::Node sink) {
  exists(MethodAccess ma |
    ma.getMethod().getName() = "append" and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
    ma.getQualifier().toString().matches("http(s?)://%(v|s|q).*") and
    ma.getAnArgument() = sink.asExpr()
  )
}
 
predicate isStringPlusAssignSink(DataFlow::Node sink) {
  exists(AssignExpr ae |
    ae.toString().matches("^\\$\\w+ \\+=.*") and
    ae.getRightOperand() = sink.asExpr() and
    ae.getLeftOperand().getType().toString().matches("http(s?)://%(v|s|q).*")
  )
}
 
predicate isSink(DataFlow::Node sink) {
  isUrlConstructionSink(sink) or
  isStringConcatSink(sink) or
  isStringBuilderAppendSink(sink) or
  isStringPlusAssignSink(sink)
}
 
// Sanitizer definitions
predicate isSanitizer(DataFlow::Node sanitizer) {
  exists(MethodAccess ma |
    ma.getMethod().getName() = "getHost" and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.net", "URL")
  )
}
 
// Taint propagation for String types
class StringTaintPropagation extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    pred.getType() instanceof TypeString and
    succ.getType() instanceof TypeString and
    exists(DataFlow::ParameterNode param, DataFlow::ArgumentNode arg |
      (pred = param and succ = arg) or
      (pred = arg and succ = param)
    )
  }
}
 
from DataFlow::PathNode source, DataFlow::PathNode sink
where
  isSource(source.getNode()) and
  isSink(sink.getNode()) and
  TaintTracking::localTaint(source, sink) and
  not exists(DataFlow::Node sanitizer |
    TaintTracking::localTaint(source, sanitizer) and
    isSanitizer(sanitizer) and
    TaintTracking::localTaint(sanitizer, sink)
  )
select sink.getNode(), "User data flows into the host portion of this manually-constructed URL. " +
  "This could allow an attacker to send data to their own server, potentially exposing sensitive data " +
  "such as cookies or authorization information sent with this request. They could also probe internal " +
  "servers or other resources that the server running this code can access. (This is called server-side " +
  "request forgery, or SSRF.) Do not allow arbitrary hosts. Instead, create an allowlist for approved " +
  "hosts, hardcode the correct host, or ensure that the user data can only affect the path or parameters."