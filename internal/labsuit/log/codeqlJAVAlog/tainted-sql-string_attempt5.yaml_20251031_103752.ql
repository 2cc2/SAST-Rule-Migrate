/**
 * @name Tainted SQL string
 * @description User data flows into this manually-constructed SQL string. User data can be safely 
 *              inserted into SQL strings using prepared statements or an object-relational mapper 
 *              (ORM). Manually-constructed SQL strings is a possible indicator of SQL injection, 
 *              which could let an attacker steal or manipulate data from the database.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/tainted-sql-string
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow

predicate isUserInputParameter(Expr exp) {
  exists(Parameter p |
    exp = p.getAnAccess() and
    not p.getType() instanceof PrimitiveType and
    exists(p.getAnAnnotation().getType().getName() |
      regexpMatch("(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue)", _)
    )
  )
}

class StringConcatenationCall extends DataFlow::CallNode {
  StringConcatenationCall() {
    getTarget().getName().matches("concat|append") or
    getTarget().getName() = "format" and
    getTarget().getDeclaringType().hasQualifiedName("java.lang", "String") and
    exists(DataFlow::DataFlow::argument(0).getStringValue() |
      regexpMatch("(?i)(select|delete|insert|create|update|alter|drop)\\b", _)
    ) and
    not getTarget().getDeclaringType().hasQualifiedName("java.lang.System", "out") and
    not getTarget().getDeclaringType().getName().matches("LOG|Exception")
  }
}

class TaintedSQLStringConfig extends TaintTracking::Configuration {
  TaintedSQLStringConfig() { this = "TaintedSQLStringConfig" }

  override predicate isSource(DataFlow::Node source) {
    isUserInputParameter(source.asExpr())
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(StringConcatenationCall call |
      sink.asExpr() = call.getArgument(0)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedSQLStringConfig config
where config.hasFlowPath(source, sink)
select sink, "User data flows into this manually-constructed SQL string, potential SQL injection.", 
  source, "User input"