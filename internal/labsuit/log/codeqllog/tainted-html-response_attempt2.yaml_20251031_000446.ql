/**
 * @name Tainted HTML Response
 * @description Detected user input flowing into an HTML response. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability.
 * @kind problem
 * @id python/tainted-html-response
 * @severity warning
 * @tags security
 *       external/cwe/cwe-79
 *       external/owasp/a07:2017
 *       external/owasp/a03:2021
 */

import semmle.python.dataflow.TaintTracking
import semmle.python.ApiGraphs
import semmle.python.Concepts

class EventParameter extends TaintTracking::SourceNode {
  EventParameter() {
    exists(FunctionValue func |
      func.getAParameter(_).regexpMatches("event") and
      result = func.getAParameter(_)
    )
  }

  override predicate isSourceOf(DataFlow::Node source) {
    source.asParameter().regexpMatches("event")
  }

  override DataFlow::Node asCfgNode() { result = this }
  override DataFlow::BasicBlock getBasicBlock() { result = this }
  override string toString() { result = "Event parameter" }
  override DataFlow::Variable asVariable() { result = none() }
  override DataFlow::Scope getScope() { result = this.getScope() }
  override Location getLocation() { result = this.getLocation() }
}

class HtmlResponseCall extends TaintTracking::SinkNode {
  HtmlResponseCall() {
    exists(CallNode call |
      call.getArgument().toString().matches("%\"headers\": {.*\"Content-Type\": \"text/html\".*}, \"body\": %") and
      result = call.getArgument()
    )
  }

  override predicate isSinkOf(DataFlow::Node sink) {
    exists(CallNode call |
      sink = call.getArgument() and
      call.getArgument().toString().matches("%\"headers\": {.*\"Content-Type\": \"text/html\".*}, \"body\": %")
    )
  }

  override DataFlow::Node asCfgNode() { result = this }
  override DataFlow::BasicBlock getBasicBlock() { result = this }
  override string toString() { result = "HTML response" }
  override DataFlow::Variable asVariable() { result = none() }
  override DataFlow::Scope getScope() { result = this.getScope() }
  override Location getLocation() { result = this.getLocation() }
}

class TaintedHtmlResponseConfiguration extends TaintTracking::Configuration {
  TaintedHtmlResponseConfiguration() {
    this = "Tainted HTML Response Configuration"
  }

  override predicate isSource(DataFlow::Node source) {
    source instanceof EventParameter
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof HtmlResponseCall
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(DataFlow::ParameterNode param, DataFlow::CallNode call |
      node1 = param and
      node2 = call.getArgument() and
      param.getFunction() = call.getCallee()
    )
  }
}

from TaintedHtmlResponseConfiguration cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential XSS vulnerability: user input flows into HTML response without proper escaping"