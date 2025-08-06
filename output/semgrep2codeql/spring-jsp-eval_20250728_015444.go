/**
 * @name Spring JSP Eval Injection
 * @description A Spring expression is built with a dynamic value. The source of the value(s) should be verified to
 *              avoid that unfiltered values fall into this risky code evaluation.
 * @kind path-problem
 * @problem.severity warning
 * @id java/spring-jsp-eval
 * @tags security
 *       external/cwe/cwe-95
 *       external/owasp/a03
 *       technology/spring
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class SpringEvalPattern extends DataFlow::ExprNode {
  SpringEvalPattern() {
    exists(StringLiteral str |
      str.getValue().regexpMatch(".*<spring:eval.*expression=.*>.*") and
      this.asExpr() = str
    )
  }
}

class SpringEvalConfig extends TaintTracking::Configuration {
  SpringEvalConfig() { 
    this = "SpringEvalConfig" 
  }

  override predicate isSource(DataFlow::Node source) { 
    source instanceof SpringEvalPattern
  }

  override predicate isSink(DataFlow::Node sink) { 
    none() 
  }
}

from SpringEvalConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential Spring JSP eval injection detected - dynamic expression evaluation"