/**
 * @name find-sql-string-concatenation
 * @description In $METHOD, $X is used to construct a SQL query via string concatenation.
 * @id security/java/find-sql-string-concatenation
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-089
 *       external/cwe/cwe-564
 *       external/owasp/a01
 *       external/owasp/a03
 *       jboss
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class StringConcatenationConfiguration extends TaintTracking::Configuration {
  StringConcatenationConfiguration() { this = "StringConcatenationConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p | source.asParameter() = p and p.getType().hasName("String"))
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma | 
      ma.getMethod().getName() = "prepareStatement" and 
      sink.asExpr() = ma.getArgument(0)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, Method m
where
  exists(StringConcatenationConfiguration cfg | cfg.hasFlowPath(source, sink)) and
  sink.getNode().asExpr().getEnclosingCallable() = m
select sink.getNode(), source, sink, "In $@, $@ is used to construct a SQL query via string concatenation.",
  m, "method", source.getNode(), "parameter"