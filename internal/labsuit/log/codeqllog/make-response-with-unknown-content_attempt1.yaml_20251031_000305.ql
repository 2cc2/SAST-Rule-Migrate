/**
 * @name Make Response with Unknown Content
 * @description Be careful with `flask.make_response()`. If this response is rendered onto a webpage,
 *              this could create a cross-site scripting (XSS) vulnerability. `flask.make_response()`
 *              will not autoescape HTML. If you are rendering HTML, write your HTML in a template file
 *              and use `flask.render_template()` which will take care of escaping. If you are returning
 *              data from an API, consider using `flask.jsonify()`.
 * @kind taint
 * @problem.severity warning
 * @id python/xss/make-response-with-unknown-content
 * @tags security
 *       cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
 *       owasp: "A07:2017 - Cross-Site Scripting (XSS)"
 *       owasp: "A03:2021 - Injection"
 */

import python
import DataFlow::PathGraph

class UnknownContentSource extends DataFlow::Node {
  UnknownContentSource() {
    exists(Call call |
      call.hasQualifiedName("flask", "make_response") and
      not (
        call.getArg(0).(Call).hasQualifiedName("flask", "render_template") or
        call.getArg(0).(Call).hasQualifiedName("flask", "jsonify") or
        call.getArg(0).(Call).hasQualifiedName("json", "dumps") or
        call.getArg(0).(Call).hasQualifiedName("flask", "redirect")
      )
    )
  }
}

class XssSink extends DataFlow::Node {
  XssSink() {
    exists(Call call |
      call.hasQualifiedName("flask", "make_response") and
      this.asExpr() = call.getArg(0).asExpr()
    )
  }
}

class TemplateRenderSanitizer extends DataFlow::Node {
  TemplateRenderSanitizer() {
    exists(Call call |
      call.hasQualifiedName("flask", "render_template") and
      this.asExpr() = call.asExpr()
    )
  }
}

class JsonifySanitizer extends DataFlow::Node {
  JsonifySanitizer() {
    exists(Call call |
      call.hasQualifiedName("flask", "jsonify") and
      this.asExpr() = call.asExpr()
    )
  }
}

class JsonDumpsSanitizer extends DataFlow::Node {
  JsonDumpsSanitizer() {
    exists(Call call |
      call.hasQualifiedName("json", "dumps") and
      this.asExpr() = call.asExpr()
    )
  }
}

module TaintFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof UnknownContentSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof XssSink }
  predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof TemplateRenderSanitizer or
    sanitizer instanceof JsonifySanitizer or
    sanitizer instanceof JsonDumpsSanitizer
  }
}

module TaintFlow = DataFlow::Global<TaintFlowConfig>;
from DataFlow::PathNode source, DataFlow::PathNode sink
where TaintFlow.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential XSS vulnerability from flask.make_response() with unsafe content"