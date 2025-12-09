/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind path-problem
 * @problem.severity warning
 * @id python/formatted-sql-query
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class SQLFormatPercent extends DataFlow::Node {
  SQLFormatPercent() {
    exists(Call call |
      call = this.asExpr() and
      call.getCode().regexpMatch("\\.\\.\\.\\s*%\\.\\.\\.")
    )
  }
}

class SQLFormatFunction extends DataFlow::Node {
  SQLFormatFunction() {
    exists(Call call |
      call = this.asExpr() and
      call.getTarget().getName().regexpMatch(".*\\.format")
    )
  }
}

class SQLFormatFString extends DataFlow::Node {
  SQLFormatFString() {
    exists(Str s |
      s = this.asExpr() and
      s.getCode().regexpMatch("f\\\"")
    )
  }
}

class SQLExecutionSink extends DataFlow::Node {
  SQLExecutionSink() {
    exists(Call call |
      call = this.asExpr() and
      call.getTarget().getName() = "execute" and
      this.asExpr() = call.getArgument(0)
    )
  }
}

class FormattedSQLQueryConfiguration extends TaintTracking::Configuration {
  FormattedSQLQueryConfiguration() { this = "FormattedSQLQueryConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SQLFormatPercent or
    source instanceof SQLFormatFunction or
    source instanceof SQLFormatFString
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SQLExecutionSink
  }
}

from FormattedSQLQueryConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, "Detected possible formatted SQL query. Use parameterized queries instead."