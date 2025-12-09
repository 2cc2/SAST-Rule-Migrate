/**
 * @name Tainted HTML Response
 * @description Detected user input flowing into an HTML response. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data.
 * @kind taint
 * @problem.severity warning
 * @id python/tainted-html-response
 * @tags security
 *       cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
 *       owasp: "A07:2017 - Cross-Site Scripting (XSS)"
 *       owasp: "A03:2021 - Injection"
 *       technology: "aws-lambda"
 */

import python
import semmle.python.dataflow.TaintTracking
import semmle.python.ApiGraphs

class EventParameter extends DataFlow::Node {
  EventParameter() {
    exists(FunctionValue func, Parameter p |
      func.getAParameter() = p and
      p.getName().regexpMatch("event") and
      this.asParameter() = p
    )
  }
}

class HtmlResponseCall extends DataFlow::Node {
  HtmlResponseCall() {
    exists(Call call |
      call.getCode().toString().matches('"headers": {.*"Content-Type": "text/html".*}, "body": %body%,.*') and
      this.asExpr() = call
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "TaintedHTMLResponse" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof EventParameter
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof HtmlResponseCall
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(FunctionCall call, Argument arg, Parameter param |
      node1.asParameter() = param and
      node2.asExpr() = arg and
      param = call.(FunctionValue).getAParameter() and
      arg = call.getAnArg()
    )
  }
}

from Config cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential XSS vulnerability: User input flows into HTML response without proper sanitization"