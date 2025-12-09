/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind problem
 * @id python/security/formatted-sql-query
 * @problem.severity warning
 * @security-severity 7.5
 * @precision low
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(Call call |
      call.getTarget().toString().matches("%\\.\\.\\.%") and
      this.asExpr() = call
    )
    or
    exists(Call call |
      call.getTarget().getName() = "format" and
      this.asExpr() = call
    )
    or
    exists(StringLiteral literal |
      literal.getValue().matches("f\\\"") and
      this.asExpr() = literal
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(Call call |
      call.getTarget().getName() = "execute" and
      call.getArg(0) = this.asExpr()
    )
  }
}

class FormattedSqlConfig extends TaintTracking::Configuration {
  FormattedSqlConfig() { this = "FormattedSqlConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlFormatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }
}

from FormattedSqlConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), "Detected possible formatted SQL query. Use parameterized queries instead.",
  source.getNode(), "User input comes from here.",
  sink.getNode(), "Potential SQL injection sink"