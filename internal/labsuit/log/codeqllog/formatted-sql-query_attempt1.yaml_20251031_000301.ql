/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind path-problem
 * @problem.severity warning
 * @id python/formatted-sql-query
 * @tags security
 *       owasp-a01
 *       owasp-a03
 *       cwe-89
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(CallExpr call |
      call.getCode().regexpMatch("\\.\\.\\.\\s*%\\.\\.\\.") and
      this.asExpr() = call
    ) or
    exists(CallExpr call |
      call.getFunc().getQualifiedName().regexpMatch(".*\\.format") and
      this.asExpr() = call
    ) or
    exists(StringLiteral str |
      str.getCode().matches("%f\"%") and
      this.asExpr() = str
    )
  }
}

class SqlExecuteSink extends DataFlow::Node {
  SqlExecuteSink() {
    exists(CallExpr call|
      call.getFunc().getName() = "execute" and
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

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    // No sanitizers in this rule
    false
  }
}

from SqlTaintConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Possible SQL injection from formatted string", source,
  "This $@ may contain formatted SQL input.", source, "user input"