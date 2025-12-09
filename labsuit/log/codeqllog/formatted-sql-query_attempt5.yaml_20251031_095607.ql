/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind problem
 * @id python/security/formatted-sql-query
 * @problem.severity warning
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(Call call |
      call.getText().matches("%\\.\\.\\.\\s*%\\.\\.\\.%") and
      this.asExpr() = call
    )
    or
    exists(Call call |
      call.getFunc().(Name).getId().matches("%\\.format%") and
      this.asExpr() = call
    )
    or
    exists(StringLiteral lit |
      lit.getText().matches("%f\\\"%") and
      this.asExpr() = lit
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(Call call |
      call.getFunc().(Name).getId() = "execute" and
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
    sink instanceof SqlExecutionSink
  }
}

from FormattedSqlQueryConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, "Potential SQL injection via formatted string. Use parameterized queries instead.", source,
  "User input flows into SQL query here"