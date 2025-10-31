/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id py/formatted-sql-query
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import python
import semmle.python.Concepts
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class SqlFormatSource extends TaintTracking::SourceNode {
  SqlFormatSource() {
    exists(Call call |
      call.isFormattedString() or
      call.getTarget().getName().matches("%format%") or
      call.toString().matches("%\\.\\.\\.\\s*%\\.\\.\\.%")
    )
    and
    result = this.asExpr()
  }
}

module IsSinkConfig implements DataFlow::ConfigSig {
  predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call = sink.asExpr() and
      call.getTarget().getName() = "execute" and
      sink.asParameter() = 0
    )
  }
}

class FormattedSqlQueryConfig extends TaintTracking::Configuration {
  FormattedSqlQueryConfig() { this = "FormattedSqlQueryConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof SqlFormatSource }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof IsSinkConfig
  }
}

from FormattedSqlQueryConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential SQL injection from formatted string to execute() call"