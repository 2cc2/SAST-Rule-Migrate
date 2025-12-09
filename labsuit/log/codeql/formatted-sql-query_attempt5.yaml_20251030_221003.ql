/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind taint
 * @problem.severity warning
 * @precision medium
 * @id python/formatted-sql-query
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PartialPathGraph

class SqlFormatSource extends TaintTracking::Source {
  SqlFormatSource() { 
    this.asSource() instanceof Call or
    this.asSource() instanceof StringLiteral 
  }

  override predicate isSourceOf(DataFlow::Node source) {
    exists(Call c, string pattern | source.asExpr() = c |
      c.getFunc().getName().matches("%format%") or
      pattern = c.getText() and pattern.regexpMatch(".*\\.\\.\\.\\s*%\\.\\.\\..*")
    )
    or
    exists(StringLiteral lit | source.asExpr() = lit |
      lit.getText().matches("f\"%")
    )
  }
}

class SqlExecutionSink extends TaintTracking::Sink {
  SqlExecutionSink() { this.asSink() instanceof Call }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call c | sink.asExpr() = c |
      c.getFunc().getName() = "execute" and
      sink = c.getArg(0)
    )
  }
}

class FormatSqlQueryConfig extends TaintTracking::Configuration {
  FormatSqlQueryConfig() { this = "FormatSqlQueryConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlFormatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Call c |
      node1.asExpr() = c.getArg(_) and
      node2.asExpr() = c.getFunc()
    )
  }
}

from FormatSqlQueryConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Potential SQL injection from formatted string", source, 
  "This dynamically constructed SQL query is vulnerable to injection attacks"