/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead
 * @kind path-problem
 * @problem.severity warning
 * @precision low
 * @id python/security/formatted-sql-query
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/** A source is a string formatting operation */
class SqlFormatSource extends DataFlow::SourceNode {
  SqlFormatSource() {
    exists(Call call |
      call.getFuncName().regexpMatch(".*\\.format") and
      this.asExpr() = call.getAnArg()
    ) or
    exists(string literal |
      literal.getValue().matches("%f\".*") and
      this.asExpr() = literal
    )
  }

  override string getSourceType() { result = "Formatted string" }
}

/** A sink is SQL execution with formatted string as argument */
class SqlExecutionSink extends DataFlow::SinkNode {
  SqlExecutionSink() {
    exists(Call call |
      call.getFuncName() = "execute" and
      this.asExpr() = call.getArg(0)
    )
  }

  override string getSinkType() { result = "SQL execution" }
}

/** Configuration for formatted SQL query taint tracking */
class FormattedSqlQueryConfig extends TaintTracking::Configuration {
  FormattedSqlQueryConfig() { this = "FormattedSqlQueryConfig" }

  override predicate isSource(DataFlow::SourceNode source) {
    source instanceof SqlFormatSource
  }

  override predicate isSink(DataFlow::SinkNode sink) {
    sink instanceof SqlExecutionSink
  }
}

from FormattedSqlQueryConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "Detected possible formatted SQL query. Use parameterized queries instead."