/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind path-problem
 * @problem.severity warning
 * @id python/security/sql-injection-format
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import python
import semmle.python.dataflow.TaintTracking
import semmle.python.ApiGraphs

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(Call call | call = this.asExpr() |
      call.getPrimaryQlClass().getCode().regexpMatch(".*\\s*%.*") 
      or
      call.getCallee().toString().matches("%.format")
    )
    or
    exists(StringLiteral str | str = this.asExpr() |
      str.getPrimaryQlClass().getCode().matches("f\"%")
    )
  }
}

class SqlExecuteSink extends DataFlow::Node {
  SqlExecuteSink() {
    exists(Call call | call = this.asExpr() |
      call.getCallee().toString().matches("execute") and
      this.asExpr() = call.getArg(0)
    )
  }
}

class SqlTaintConfig extends TaintTracking::Configuration {
  SqlTaintConfig() { this = "SqlTaintConfig" }

  override predicate isSource(DataFlow::Node source) { 
    source instanceof SqlFormatSource 
  }

  override predicate isSink(DataFlow::Node sink) { 
    sink instanceof SqlExecuteSink 
  }
}

from SqlTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Possible SQL injection risk from formatted query", source,
  "This SQL query is constructed from formatted string. Consider using parameterized queries."