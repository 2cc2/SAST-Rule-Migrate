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
import semmle.python.functions.Types
import semmle.python.Concepts
import DataFlow::PathGraph

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    // SQL format using % operator
    exists(Call call |
      call = this.asParameter() and
      call.getFunc().toString().regexpMatch(".*\\%\\.*")
    ) or
    // SQL format using format() method
    exists(Call call |
      call = this.asParameter() and
      call.getFunc().getName() = "format"
    ) or
    // SQL format using f-strings
    exists(StringLiteral literal |
      literal = this.asParameter() and
      literal.getStringValue().regexpMatch("f\\\".*\\\"")
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(Call call |
      call = this.asParameter() and
      call.getFunc().getName() = "execute"
    )
  }
}

class FormattedSqlQueryConfig extends TaintTracking::Configuration {
  FormattedSqlQueryConfig() { this = "FormattedSqlQueryConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof SqlFormatSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlExecutionSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) { none() }
}

from FormattedSqlQueryConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Detected possible formatted SQL query. Use parameterized queries instead.", 
  source, "User input flows to SQL execution."