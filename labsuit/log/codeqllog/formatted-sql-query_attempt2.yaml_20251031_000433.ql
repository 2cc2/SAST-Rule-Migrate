/**
 * @name Formatted SQL Query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision low
 * @id python/formatted-sql-query
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import python
import semmle.python.dataflow.TaintTracking
import semmle.python.ApiGraphs

class FormattedSqlConfig extends TaintTracking::Configuration {
  FormattedSqlConfig() { this = "FormattedSqlConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(CallNode call | exists(string pattern |
      call.getCode().regexpMatch(".*\\.\\.\\..*%.*\\.\\.\\..*") and
      source.asExpr() = call
    )) or
    exists(CallNode call |
      call.getFunc().(Name).getText() = "format" and
      source.asExpr() = call
    ) or
    exists(DataFlow::StringLiteral literal |
      literal.getStringValue().regexpMatch("f\".*") and
      source.asExpr() = literal
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(CallNode call |
      call.getFunc().(Name).getText() = "execute" and
      sink.asExpr() = call.getArg(0)
    )
  }
}

from FormattedSqlConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Possible formatted SQL query. Use parameterized queries instead.", source,
  "User-provided value flows into SQL query formatting."