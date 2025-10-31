/**
 * @name Tainted URL Host
 * @description User data flows into the host portion of this manually-constructed URL.
 * @id tainted-url-host
 * @kind path-problem
 * @problem.severity warning
 * @tags security
 *       external/cwe/cwe-918
 *       external/owasp/a10
 */

import python
import semmle.python.ApiGraphs
import semmle.python.StringOps
import DataFlow::PathGraph

class FlaskRequestSource extends DataFlow::Node {
  FlaskRequestSource() {
    exists(string propName | 
      getAttrCall("flask", "request", propName, _) |
      this.asExpr() = any(DataFlow::MethodAccess ma |
        ma.getMethod().getQualifiedName() = "flask.request." + propName
      )
    )
  }
}

class RouteParamSource extends DataFlow::Node {
  RouteParamSource() {
    exists(Function f |
      f.getADecorator().getACall().getName() = "route" and
      this.asParameter() = f.getAParameter()
    )
  }
}

class PercentConstructedUrlSink extends DataFlow::Node {
  PercentConstructedUrlSink() {
    exists(StringFormatExpr str |
      str.getFmt().regexpMatch(".*://%[sr].*") and
      this.asExpr() = str
    )
  }
}

class FormatConstructedUrlSink extends DataFlow::Node {
  FormatConstructedUrlSink() {
    exists(MethodCall mc |
      mc.getMethod().getName() = "format" and
      mc.getQualifier().regexpMatch(".*://.*\\{.*\\}.*") and
      this.asExpr() = mc
    )
  }
}

class ConcatConstructedUrlSink extends DataFlow::Node {
  ConcatConstructedUrlSink() {
    exists(BinaryExpr be |
      be.getOperator() = "+" and
      be.getLeft().getText().matches(".*://") and
      this.asExpr() = be
    )
  }
}

class FStringConstructedUrlSink extends DataFlow::Node {
  FStringConstructedUrlSink() {
    exists(InterpolatedStringExpr ise |
      ise.getStringPart().regexpMatch(".*://") and
      this.asExpr() = ise
    )
  }
}

class InplaceConstructedUrlSink extends DataFlow::Node {
  InplaceConstructedUrlSink() {
    exists(BinaryExpr be |
      be.getOperator() = "+=" and
      be.getLeft().getText().matches(".*://") and
      this.asExpr() = be
    )
  }
}

class TaintedUrlHostConfig extends TaintTracking::Configuration {
  TaintedUrlHostConfig() { this = "TaintedUrlHostConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof FlaskRequestSource or
    source instanceof RouteParamSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof PercentConstructedUrlSink or
    sink instanceof FormatConstructedUrlSink or
    sink instanceof ConcatConstructedUrlSink or
    sink instanceof FStringConstructedUrlSink or
    sink instanceof InplaceConstructedUrlSink
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedUrlHostConfig conf
where conf.hasFlowPath(source, sink)
select sink, 
  "User data flows into the host portion of this manually-constructed URL. " +
  "This could allow an attacker to send data to their own server, potentially " +
  "exposing sensitive data such as cookies or authorization information sent " +
  "with this request.", source, "User input flows here"