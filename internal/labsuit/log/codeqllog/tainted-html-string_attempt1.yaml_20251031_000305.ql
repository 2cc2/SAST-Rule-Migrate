/**
 * @name Tainted HTML string construction
 * @description Detects user input flowing into manually constructed HTML strings, which may lead to XSS vulnerabilities.
 * @kind problem
 * @problem.severity warning
 * @id python/tainted-html-string
 * @tags security
 *       external/cwe/cwe-79
 *       external/owasp/a07:2017
 *       external/owasp/a03:2021
 *       technology/aws-lambda
 */

import python
import semmle.python.dataflow.DataFlow
import semmle.python.dataflow.TaintTracking

class EventParameter extends DataFlow::Node {
  EventParameter() {
    exists(FunctionValue handler |
      handler.getName() = regexpMatch("def \\w+\\(event, context\\):")
      and
      this.asParameter() = handler.getAParameter()
      and
      this.asParameter().getName() = "event"
    )
  }
}

class HtmlLiteralConstruction extends DataFlow::Node {
  HtmlLiteralConstruction() {
    exists(string html |
      (
        // String formatting variants
        (
          // % formatting
          this.asExpr() = any(FormatStringOperation fso).getStringPart()
          or
          // .format()
          this.asExpr() = any(MethodCall mc |
            mc.getMethod().getName() = "format" and
            exists(mc.getQualifier())
          ).getQualifier()
          or
          // String concatenation
          this.asExpr() = any(BinaryOperation bo |
            bo.getOperator() = "+"
          ).getLeftOperand()
          or
          // f-string
          this.asExpr() = any(FString fs).getStringPart()
        )
        and
        html = this.getStringValue()
        and
        html.regexpMatches("<[a-zA-Z]+")
      )
      and
      not exists(DataFlow::CallNode call | call.getTarget().getName() = "print")
    )
  }
}

class SafeRendering extends DataFlow::BarrierGuard, DataFlow::BarrierNode {
  SafeRendering() {
    exists(DataFlow::CallNode call |
      call.getNode() = this.asExpr()
    )
  }
}

module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof EventParameter
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof HtmlLiteralConstruction
  }

  predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SafeRendering
  }

  predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodCall mc, DataFlow::ParameterNode param |
      pred.asExpr() = mc.getAnArgument() and
      succ.asParameter() = param and
      param = mc.getArgument(0)
    )
  }
}

from DataFlow::Configuration config, DataFlow::Node source, DataFlow::Node sink
where
  config.hasFlow(source, sink)
select sink,
  "Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing " +
  "secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, " +
  "which could let attackers steal sensitive user data. To be sure this is safe, check that the HTML is rendered " +
  "safely. Otherwise, use templates which will safely render HTML instead."