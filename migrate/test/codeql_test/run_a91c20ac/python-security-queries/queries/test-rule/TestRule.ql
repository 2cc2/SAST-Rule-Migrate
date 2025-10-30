/**
 * @name Formatted SQL Query
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
import semmle.python.Concepts

class SqlFormatSource extends DataFlow::SourceNode {
  SqlFormatSource() {
    exists(Call c |
      c.getTarget().toString().matches(".*\\.format") or
      c.toString().matches("\\.\\.\\.\\s*%\\.\\.\\.")
    ) or
    exists(Literal l |
      l.getStringValue().matches("f\\\"")
    )
  }
}

class SqlExecutionSink extends DataFlow::SinkNode {
  SqlExecutionSink() {
    exists(Call c |
      c.getTarget().getName() = "execute" and
      c.getArg(0) = this.asExpr()
    )
  }
}

class SqlTaintConfig extends TaintTracking::Configuration {
  SqlTaintConfig() { this = "SqlTaintConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof SqlFormatSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlExecutionSink }
}

from SqlTaintConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected possible formatted SQL query. Use parameterized queries instead."