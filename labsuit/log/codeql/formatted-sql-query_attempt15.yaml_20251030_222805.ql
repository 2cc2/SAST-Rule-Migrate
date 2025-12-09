/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
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
import semmle.python.ApiGraphs
import DataFlow::PathGraph

class SQLFormatSource extends DataFlow::Node {
  SQLFormatSource() {
    exists(Call call |
      (
        call.getFunc().(Name).getId().regexpMatch(".*\\.format") or
        call.getCode().regexpMatch("\\.\\.\\.\\s*%\\.\\.\\.")
      ) and
      this.asExpr() = call
    ) or
    exists(Str str |
      (str.hasLeadingF() or str.hasLeadingFR()) and
      this.asExpr() = str
    )
  }
}

class SQLExecuteSink extends DataFlow::Node {
  SQLExecuteSink() {
    exists(Call call |
      call.getFunc().(Name).getId() = "execute" and
      this.asExpr() = call.getArg(0)
    )
  }
}

class FormattedSQLQueryConfig extends DataFlow::Configuration {
  FormattedSQLQueryConfig() { this = "FormattedSQLQueryConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SQLFormatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SQLExecuteSink
  }
}

from FormattedSQLQueryConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), "Detected possible formatted SQL query. Use parameterized queries instead.", 
  source.getNode(), "User-provided format string here"