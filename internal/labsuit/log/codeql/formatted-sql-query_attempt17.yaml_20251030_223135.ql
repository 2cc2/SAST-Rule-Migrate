/**
 * @name formatted-sql-query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision medium
 * @id python/sql-injection-formatted-query
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a03:2021
 *       external/owasp/a01:2017
 */

import python
import semmle.python.dataflow.TaintTracking
import DataFlow::PathGraph

private class SQLFormatSource extends TaintTracking::Source {
  SQLFormatSource() {
    exists(Call call |
      (
        call.getTarget().toString().regexpMatches(".*\\.format") or
        exists(string literal |
          call.getTarget().toString().matches("%.*%") and
          call = literal.getParent()
        )
      ) and
      this.asExpr() = call
    ) or
    exists(string literal |
      literal.matches("f\\\"") and
      this.asExpr() = literal
    )
  }

  override predicate isSource(TaintTracking::Source source) { source = this }

  override predicate asCfgNode(DataFlow::CfgNode cfgNode) { cfgNode.asExpr() = this.asExpr() }

  override DataFlow::Location getLocation() { result = this.asExpr().getLocation() }

  override DataFlow::BasicBlock getBasicBlock() { result = this.asExpr().getBasicBlock() }

  override string toString() { result = this.asExpr().toString() }

  override DataFlow::Scope getScope() { result = this.asExpr().getScope() }

  override DataFlow::Variable asVariable() { result = this.asExpr().asVariable() }
}

private class SQLExecuteSink extends TaintTracking::Sink {
  SQLExecuteSink() {
    exists(Call call |
      call.getTarget().getName() = "execute" and
      this.asExpr() = call.getArg(0)  
    )
  }

  override predicate isSink(TaintTracking::Sink sink) { sink = this }

  override predicate asCfgNode(DataFlow::CfgNode cfgNode) { cfgNode.asExpr() = this.asExpr() }

  override DataFlow::Location getLocation() { result = this.asExpr().getLocation() }

  override DataFlow::BasicBlock getBasicBlock() { result = this.asExpr().getBasicBlock() }

  override string toString() { result = this.asExpr().toString() }

  override DataFlow::Scope getScope() { result = this.asExpr().getScope() }

  override DataFlow::Variable asVariable() { result = this.asExpr().asVariable() }
}

class SQLTaintConfiguration extends TaintTracking::Configuration {
  SQLTaintConfiguration() { this = "SQLTaintConfiguration" }

  override predicate isSource(TaintTracking::Source source) { source instanceof SQLFormatSource }

  override predicate isSink(TaintTracking::Sink sink) { sink instanceof SQLExecuteSink }
}

from SQLTaintConfiguration cfg, TaintTracking::Source source, TaintTracking::Sink sink
where cfg.hasFlow(source, sink)
select sink, "Detected possible formatted SQL query. Use parameterized queries instead."