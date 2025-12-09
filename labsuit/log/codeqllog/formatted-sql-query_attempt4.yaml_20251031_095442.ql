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

class SqlFormatSource extends DataFlow::ExprNode {
  SqlFormatSource() {
    exists(Call c |
      c.getFunc().toString().regexpMatch(".*\\.format") or
      c.toString().regexpMatch("\\.\\.\\.\\s*%\\.\\.\\.")
    ) and this = c
    or
    exists(Str s |
      s.getValue().regexpMatch("f\"") and
      this = s
    )
  }
}

class SqlExecutionSink extends DataFlow::ExprNode {
  SqlExecutionSink() {
    exists(Call c |
      c.getFunc().getName() = "execute" and
      this = c.getArg(0)
    )
  }
}

class SqlTaintConfiguration extends TaintTracking::Configuration {
  SqlTaintConfiguration() { this = "SqlTaintConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof SqlFormatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof SqlExecutionSink
  }
}

from SqlTaintConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Detected possible formatted SQL query. Use parameterized queries instead.", 
  source, "This formatted string flows here"