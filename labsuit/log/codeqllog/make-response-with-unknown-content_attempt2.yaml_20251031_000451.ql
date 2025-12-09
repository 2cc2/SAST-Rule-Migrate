/** 
 * @name Unsafe Flask make_response usage
 * @description Using flask.make_response() with untrusted input could lead to XSS vulnerabilities
 * @id make-response-with-unknown-content
 * @kind problem
 * @tags security
 *       external/cwe/cwe-079
 *       external/owasp/a07:2017
 *       external/owasp/a03:2021
 * @severity warning
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class FlaskMakeResponseCall extends DataFlow::CallNode {
  FlaskMakeResponseCall() {
    this.getTarget().hasQualifiedName("flask", "make_response")
  }
}

class XssSink extends DataFlow::Node {
  XssSink() {
    exists(FlaskMakeResponseCall call |
      this.asExpr() = call.getArg(0)
    )
  }
}

class UnsafeContentSource extends DataFlow::Node {
  UnsafeContentSource() {
    exists(FlaskMakeResponseCall call |
      this.asExpr() = call.getArg(0) and
      not call.getArg(0).getTarget().hasQualifiedName("flask", "render_template") and
      not call.getArg(0).getTarget().hasQualifiedName("flask", "jsonify") and
      not call.getArg(0).getTarget().hasQualifiedName("json", "dumps") and
      not call.getArg(0).getTarget().hasQualifiedName("flask", "redirect")
    )
  }
}

class Sanitizer extends DataFlow::Node {
  Sanitizer() {
    exists(DataFlow::CallNode call |
      this.asExpr() = call.getResult() and
      (
        call.getTarget().hasQualifiedName("flask", "render_template") or
        call.getTarget().hasQualifiedName("flask", "jsonify") or
        call.getTarget().hasQualifiedName("json", "dumps")
      )
    )
  }
}

class FlaskMakeResponseConfig extends TaintTracking::Configuration {
  FlaskMakeResponseConfig() { this = "FlaskMakeResponseConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UnsafeContentSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof XssSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof Sanitizer
  }
}

from FlaskMakeResponseConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Be careful with flask.make_response(). If this response is rendered " +
             "onto a webpage, this could create a cross-site scripting (XSS) " +
             "vulnerability. flask.make_response() will not autoescape HTML. " +
             "If you are rendering HTML, write your HTML in a template file and " +
             "use flask.render_template() which will take care of escaping. If " +
             "you are returning data from an API, consider using flask.jsonify()."