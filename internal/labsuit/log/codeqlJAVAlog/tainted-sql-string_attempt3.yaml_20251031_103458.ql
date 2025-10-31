/**
 * @name Tainted SQL string
 * @description User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM).
 * @kind problem
 * @id java/tainted-sql-string
 * @tags security
 *   spring
 *   external/cwe/cwe-89
 *   external/owasp/a01:2017
 *   external/owasp/a03:2021
 * @severity error
 */

import java
import codeql.java.dataflow.FlowSources
import codeql.java.dataflow.TaintTracking
import DataFlow::PathGraph

class UserInputParameter extends DataFlow::ParameterNode {
  UserInputParameter() {
    not this.getType().hasName(/^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)/) and
    exists(Annotation a | a = this.getAnAnnotation() |
      a.getType().hasName(["RequestBody", "PathVariable", "RequestParam", "RequestHeader", "CookieValue"])
    )
  }
}

class StringConcatenation extends DataFlow::Node {
  StringConcatenation() {
    exists(Expr e | e = this.asExpr() |
      (
        e.getTarget().getName().matches("%concat%") or
        e.getTarget().getName().matches("%append%") or
        e.getTarget().getName().matches("String%.format%")
      ) and
      e.getQualifier().getType().hasName("java.lang.String") and
      e.getArgument(0).toString().matches(/(?i)(select|delete|insert|create|update|alter|drop)\b/) and
      not e.getTarget().getName().matches(/(System\.out\.println|LOG\.(info|warn|warning|debug|debugging|error)|Exception)/)
    )
  }
}

class TaintedSQLFlowConfig extends TaintTracking::Configuration {
  TaintedSQLFlowConfig() { this = "TaintedSQLFlowConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof UserInputParameter }

  override predicate isSink(DataFlow::Node sink) { sink instanceof StringConcatenation }
}

from TaintedSQLFlowConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), "User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper.", 
  source.getNode(), "User input"