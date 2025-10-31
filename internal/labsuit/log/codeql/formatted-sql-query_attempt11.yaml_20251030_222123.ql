/** 
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.0
 * @precision medium
 * @id python/regex/formatted-sql-query
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import python
import semmle.python.dataflow.DataFlow
import semmle.python.dataflow.TaintTracking

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(Call call |
      call = this.asDefiningArgument() and
      (
        call.getFunction().getName().regexpMatch(".*\\.format") or
        call.toString().regexpMatch("\\.\\.\\.\\s*%\\.\\.\\.")
      )
    )
    or
    exists(StringLiteral literal |
      this.asDefiningArgument() = literal and
      literal.getStringValue().matches("f\"%.*\"")
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(Call call |
      call = this.asDefiningArgument() and
      call.getFunction().getName() = "execute" and
      this.asDefiningArgument() = call.getArg(0)
    )
  }
}

class FormattedSqlQueryConfig extends TaintTracking::Config {
  FormattedSqlQueryConfig() { this = "FormattedSqlQueryConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlFormatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }
}

from FormattedSqlQueryConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Detected possible formatted SQL query. Use parameterized queries instead.",
  source, "This string formatting could lead to SQL injection."