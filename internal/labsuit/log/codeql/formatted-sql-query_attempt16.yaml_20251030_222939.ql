/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind problem
 * @id python/security/sql-formatted-query
 * @problem.severity warning
 * @security-severity 7.5
 * @precision low
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.dataflow.DataFlow
import semmle.python.dataflow.TaintTracking

class SQLFormatSource extends DataFlow::Node {
  SQLFormatSource() {
    exists(Call call |
      call.toString().regexpMatch(".*\\.\\.\\.\\s*%\\.\\.\\..*") and
      this.asExpr() = call
    ) or
    exists(Call call |
      call.getMethodName().regexpMatch(".*\\.format") and
      this.asExpr() = call
    ) or
    exists(StringLiteral lit |
      lit.getText().regexpMatch("^f\"") and
      this.asExpr() = lit
    )
  }
}

class SQLExecuteSink extends DataFlow::Node {
  SQLExecuteSink() {
    exists(Call call |
      call.getMethodName() = "execute" and
      this.asExpr() = call.getArg(0)
    )
  }
}

class SQLTaintConfiguration extends TaintTracking::Configuration {
  SQLTaintConfiguration() { this = "SQLTaintConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SQLFormatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SQLExecuteSink
  }
}

from SQLTaintConfiguration config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Detected possible formatted SQL query. Use parameterized queries instead."