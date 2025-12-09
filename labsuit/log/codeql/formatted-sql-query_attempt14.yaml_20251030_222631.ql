/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind path-problem
 * @problem.severity warning
 * @id python/security/formatted-sql-query
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(Call call |
      call.getFunc().toString().matches("%\\.\\.\\..*") and
      this.asExpr() = call
    ) or
    exists(Call call |
      call.getFunc().toString().matches(".*\\.format") and
      this.asExpr() = call
    ) or
    exists(StringLiteral str |
      str.isFString() and
      this.asExpr() = str
    )
  }
}

private class SqlExecuteSink extends DataFlow::Node {
  SqlExecuteSink() {
    exists(Call call |
      call.getFunc().getName() = "execute" and
      this.asExpr() = call.getArg(0)
    )
  }
}

class FormattedSqlQueryConfig extends TaintTracking::Configuration {
  FormattedSqlQueryConfig() { this = "FormattedSqlQueryConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlFormatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecuteSink
  }
}

from FormattedSqlQueryConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential SQL injection from formatted query. Use parameterized queries instead."