/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind path-problem
 * @problem.severity warning
 * @id python/security/formatted-sql-query
 * @precision low
 * @tags security
 *       external/cwe/cwe-089
 *       owasp-a01:2017
 *       owasp-a03:2021
 */

import python
import semmle.python.dataflow.TaintTracking
import DataFlow::PathGraph

class SqlFormatSource extends DataFlow::SourceNode {
  SqlFormatSource() {
    exists(Call call |
      call.getFunc().toString().regexpMatch(".*\\.format") and
      (
        // Match calls with % formatting
        call.toString().regexpMatch(".*\\s*%.*") or
        exists(call.getAPrimaryQlClass() cls | cls.getName() = "print")
      )
    )
    or
    exists(StringLiteral lit |
      lit.getValue().matches("f\\\".*")
    )
  }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof SqlFormatSource
  }
}

class SqlExecutionSink extends DataFlow::SinkNode {
  SqlExecutionSink() {
    exists(Call call |
      call.getFunc().getName() = "execute" and
      this.asExpr() = call.getArg(0)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof SqlExecutionSink
  }
}

class FormattedSqlQueryConfig extends TaintTracking::Configuration {
  FormattedSqlQueryConfig() { this = "FormattedSqlQueryConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlFormatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }
}

from FormattedSqlQueryConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, "Detected possible formatted SQL query. Use parameterized queries instead.", source, sink,
  "Use parameterized queries instead of string formatting to prevent SQL injection."