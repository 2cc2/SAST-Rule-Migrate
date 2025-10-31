/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind problem
 * @id python/formatted-sql-query
 * @problem.severity warning
 * @security-severity 8.0
 * @precision low
 * @tags security
 *       external/cwe/cwe-089
 *       owasp-a01
 *       owasp-a03
 */

import python
import semmle.python.dataflow.TaintTracking
import DataFlow::PathGraph

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(Call call |
      call.getCode().regexpMatch("\\.\\.\\.\\s*%\\.\\.\\.") and
      result.asExpr() = call
    ) or
    exists(Call call |
      call.getMethodName().regexpMatch(".*\\.format") and
      result.asExpr() = call
    ) or
    exists(StringLiteral literal |
      literal.getCode().matches("%f\"%") and
      result.asExpr() = literal
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(Call call |
      call.getMethodName() = "execute" and
      call.getArgument(0) = result.asExpr()
    )
  }
}

class SQLInjectionTaintConfig extends TaintTracking::Configuration {
  SQLInjectionTaintConfig() { this = "SQLInjectionTaintConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof SqlFormatSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlExecutionSink }

  override predicate isSanitizer(DataFlow::Node node) { none() }
}

from SQLInjectionTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source.getNode(),
  "Detected possible formatted SQL query. Use parameterized queries instead.",
  source.getNode(), "User input flows to SQL query here"