/**
 * @name Tainted URL Host
 * @description User data flows into the host portion of this manually-constructed URL.
 * @kind problem
 * @problem.severity error
 * @id java/tainted-url-host
 * @tags security
 *       ssrf
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.HttpRequest

class UserInputSource extends TaintTracking::Source {
  UserInputSource() {
    exists(MethodParameter m |
      m.getType().hasName("java.lang.String") and
      not m.getType().hasName("Integer") and
      not m.getType().hasName("Long") and
      not m.getType().hasName("Float") and
      not m.getType().hasName("Double") and
      not m.getType().hasName("Char") and
      not m.getType().hasName("Boolean") and
      not m.getType().hasName("int") and
      not m.getType().hasName("long") and
      not m.getType().hasName("float") and
      not m.getType().hasName("double") and
      not m.getType().hasName("char") and
      not m.getType().hasName("boolean") and
      exists(Annotation a |
        a = m.getAnAnnotation() and
        (
          a.getType().hasName("RequestBody") or
          a.getType().hasName("PathVariable") or
          a.getType().hasName("RequestParam") or
          a.getType().hasName("RequestHeader") or
          a.getType().hasName("CookieValue") or
          a.getType().hasName("ModelAttribute")
        )
      )
    )
  }
}

class UrlConstructionSink extends TaintTracking::Sink {
  UrlConstructionSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("<init>") and
      ma.getMethod().getDeclaringType().hasName("java.net.URL") and
      ma.getArgument(0).getType().hasName("java.lang.String") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringConcatSink extends TaintTracking::Sink {
  StringConcatSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getName().matches("concat") or
        ma.getMethod().getName().matches("format")
      ) and
      ma.getMethod().getDeclaringType().hasName("java.lang.String") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringBuilderAppendSink extends TaintTracking::Sink {
  StringBuilderAppendSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("append") and
      ma.getMethod().getDeclaringType().hasName("java.lang.StringBuilder") and
      ma.getQualifier().toString().matches("http(s?)://%(v|s|q).*") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringPlusAssignSink extends TaintTracking::Sink {
  StringPlusAssignSink() {
    exists(AssignmentExpr assign |
      assign.getDest().getType().hasName("java.lang.String") and
      assign.toString().matches("^\\$\\w+ \\+=.*") and
      assign.getDest().getType().toString().matches("http(s?)://%(v|s|q).*") and
      this.asExpr() = assign.getSource()
    )
  }
}

class UrlSanitizer extends TaintTracking::Sanitizer {
  UrlSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("getHost") and
      ma.getMethod().getDeclaringType().hasName("java.net.URL")
    )
  }
}

class TaintedUrlHostConfig extends TaintTracking::Configuration {
  TaintedUrlHostConfig() { this = "TaintedUrlHostConfig" }

  override predicate isSource(TaintTracking::Source source) {
    source instanceof UserInputSource
  }

  override predicate isSink(TaintTracking::Sink sink) {
    sink instanceof UrlConstructionSink or
    sink instanceof StringConcatSink or
    sink instanceof StringBuilderAppendSink or
    sink instanceof StringPlusAssignSink
  }

  override predicate isSanitizer(TaintTracking::Sanitizer sanitizer) {
    sanitizer instanceof UrlSanitizer
  }
}

from TaintedUrlHostConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), "User data flows into the host portion of this manually-constructed URL. " +
  "This could allow an attacker to send data to their own server (SSRF vulnerability). " +
  "Create an allowlist for approved hosts or hardcode the correct host."