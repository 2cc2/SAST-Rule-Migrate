/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind problem
 * @id python/formatted-sql-query
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.dataflow.DataFlow
import semmle.python.dataflow.TaintTracking

class SqlFormatSource extends TaintTracking::Source {
  SqlFormatSource() {
    exists(Call call | call.toString().regexpMatch("\\.\\.\\.\\s*%\\.\\.\\.") |
      this = call.getArg()
    )
    or
    exists(Call call | call.getCalleeName().toString().regexpMatch(".*\\.format") |
      this = call.getArg()
    )
    or
    exists(string val | val.regexpMatch("f\\\"") |
      this = DataFlow::stringLiteral(val)
    )
  }
}

class SqlExecutionSink extends TaintTracking::Sink {
  SqlExecutionSink() {
    exists(Call call | call.getCalleeName() = "execute" |
      this = call.getArg(0)
    )
  }
}

class FormattedSqlQueryConfig extends TaintTracking::Configuration {
  FormattedSqlQueryConfig() { this = "FormattedSqlQueryConfig" }

  override predicate isSource(TaintTracking::Source source) {
    source instanceof SqlFormatSource
  }

  override predicate isSink(TaintTracking::Sink sink) {
    sink instanceof SqlExecutionSink
  }
}

from FormattedSqlQueryConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), "Possible formatted SQL query. Use parameterized queries instead."