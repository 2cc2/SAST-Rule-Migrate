/** 
 * @id tainted-url-host
 * @kind problem
 * @severity error
 * @tags security
 *      ssrf
 *      web-security
 * @cwe CWE-918
 * @owasp A10:2021
 */

import python
import semmle.python.dataflow.TaintTracking
import semmle.python.web.HttpRequest
from DataFlow::PathNode source, sink
from TaintTracking::Configuration cfg

class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    exists(Parameter p |
      p = self.asParameter() and
      p.getType().hasName("str") and
      exists(Annotation a |
        a = p.getAnAnnotation() and
        regexpMatch("(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)", 
                   a.getName())
      ) and
      not p.getType().hasName(/(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)/)
    )
  }
}

class UrlConstructionSink extends DataFlow::Node {
  UrlConstructionSink() {
    exists(CallNode cn |
      cn = self.asExpr() and
      cn.getCallee().getName() = "__init__" and
      cn.getCallee().getDeclaringType().getName() = "URL" and
      cn.getArgument(0) = self
    )
  }
}

class StringConcatSink extends DataFlow::Node {
  StringConcatSink() {
    exists(MethodAccess ma |
      ma = self.asExpr() and
      ma.getMethod().getName().matches("concat|format") and
      ma.getArgument(0) = self
    )
  }
}

class StringBuilderSink extends DataFlow::Node {
  StringBuilderSink() {
    exists(MethodAccess ma |
      ma = self.asExpr() and
      ma.getMethod().getName() = "append" and
      ma.getReceiver().toString().matches("http(s?)://%(v|s|q).*")
    )
  }
}

class StringPlusSink extends DataFlow::Node {
  StringPlusSink() {
    exists(AssignExpr ae |
      ae = self.asExpr() and
      ae.toString().matches("^\\$\\w+ \\+=.*") and
      ae.getType().getName().matches("http(s?)://%(v|s|q).*")
    )
  }
}

class UrlSanitizer extends TaintTracking::Sanitizer {
  UrlSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getHost" and
      ma.getReceiver().getType().getName() = "URL" and
      ma.getAnArgument() = self
    )
  }
}

class TaintedUrlHostConfig extends TaintTracking::Configuration {
  TaintedUrlHostConfig() { this = "TaintedUrlHostConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UserInputSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof UrlConstructionSink or
    sink instanceof StringConcatSink or
    sink instanceof StringBuilderSink or
    sink instanceof StringPlusSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof UrlSanitizer
  }
}

from TaintedUrlHostConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, 
  "User data flows into the host portion of this manually-constructed URL. " +
  "This could allow SSRF attack exposing sensitive data or probing internal resources."