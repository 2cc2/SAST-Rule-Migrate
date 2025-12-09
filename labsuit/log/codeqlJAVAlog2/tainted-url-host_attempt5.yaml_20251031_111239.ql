/**
 * @name Tainted URL Host
 * @description User data flows into the host portion of this manually-constructed URL.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id java/ssrf
 * @tags security
 *       external/cwe/cwe-918
 *       external/owasp/a10
 */
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class SpringParamSource extends DataFlow::Node {
  SpringParamSource() {
    exists(ParameterNode p |
      this.getNode() = p and
      p.getType().hasName("String") and
      not p.getType().getName().regexpMatch("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)$") and
      exists(AnnotationElement a |
        p.getAnAnnotation() = a and
        a.getType().getName().regexpMatch("(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)")
      )
    )
  }
}

class URLConsSink extends DataFlow::Node {
  URLConsSink() {
    exists(ConstructorCall cc |
      this.getNode() = cc and
      cc.getConstructedType().hasQualifiedName("java.net", "URL") and
      this = cc.getArgument(0)
    )
  }
}

class StringConcatSink extends DataFlow::Node {
  StringConcatSink() {
    exists(MethodCall ma |
      this.getNode() = ma and
      (
        (ma.getMethod().hasName("concat") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")) or
        (ma.getMethod().hasName("format") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
      ) and
      this = ma.getArgument(0)
    )
  }
}

class StringBuilderAppendSink extends DataFlow::Node {
  StringBuilderAppendSink() {
    exists(MethodCall ma |
      this.getNode() = ma and
      ma.getMethod().hasName("append") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      ma.getQualifier().toString().regexpMatch("http(s?)://%(v|s|q).*")
    )
  }
}

class StringPlusAssignSink extends DataFlow::Node {
  StringPlusAssignSink() {
    exists(AssignExpr a |
      this.getNode() = a and
      a.toString().regexpMatch("^\\$\\w+ \\+=.*") and
      a.getType().toString().regexpMatch("http(s?)://%(v|s|q).*")
    )
  }
}

class URLValidationSanitizer extends DataFlow::Node {
  URLValidationSanitizer() {
    exists(MethodCall ma |
      this.getNode() = ma and
      ma.getMethod().hasName("getHost") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.net", "URL")
    )
  }
}

predicate isTaintedString(DataFlow::Node node) {
  node.getType() instanceof TypeNode
}

from SpringParamSource source, DataFlow::Node sink
where
  (
    sink instanceof URLConsSink or
    sink instanceof StringConcatSink or
    sink instanceof StringBuilderAppendSink or
    sink instanceof StringPlusAssignSink
  ) and
  not exists(URLValidationSanitizer sanitizer |
    TaintTracking::localTaint(source.getNode(), sanitizer.getNode()) and
    TaintTracking::localTaint(sanitizer.getNode(), sink.getNode())
  ) and
  TaintTracking::localTaint(source.getNode(), sink.getNode()) and
  isTaintedString(source)
select sink, "User data flows into the host portion of this manually-constructed URL. This could allow SSRF."