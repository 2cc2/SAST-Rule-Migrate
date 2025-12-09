/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind problem
 * @id python/security/formatted-sql-query
 * @security-severity 8.0
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.dataflow.DataFlow
import semmle.python.dataflow.TaintTracking

class SQLFormatSource extends DataFlow::Source {
  SQLFormatSource() {
    exists(string pattern |
      // % formatting
      pattern.regexpMatch(".*\\s*%.*") and
      this.asExpr().toString().matches(pattern)
    )
    or
    exists(DataFlow::CallNode call |
      // .format() method
      call.getFunc().toString().regexpMatch(".*\\.format") and
      this.asExpr() = call
    )
    or
    exists(string pattern |
      // f-string formatting
      pattern = "f\"" and
      this.asExpr().toString().matches(pattern)
    )
  }

  override predicate isSourceOf(DataFlow::Node source) {
    source = this.asExpr()
  }
}

class SQLExecuteSink extends DataFlow::Sink {
  SQLExecuteSink() {
    exists(DataFlow::CallNode call |
      call.getFunc().getName() = "execute" and
      this.asExpr() = call.getAnArg()
    )
  }

  override predicate sinks(DataFlow::Node sink) {
    sink = this.asExpr()
  }
}

class SQLTaintConfiguration extends TaintTracking::Configuration {
  SQLTaintConfiguration() { this = "SQLTaintConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SQLFormatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SQLExecuteSink
  }
}

from SQLTaintConfiguration config, SQLFormatSource source, SQLExecuteSink sink
where config.hasFlow(source, sink)
select sink, "Possible SQL injection vulnerability from formatted string to $@.", source,
  "User-provided value flows to SQL execution here."