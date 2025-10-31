/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind problem
 * @severity warning
 * @id python/security/formatted-sql-query
 * @tags security
 *       external/cwe/cwe-089
 *       owasp-a03
 *       owasp-a01
 */

import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import DataFlow::PathGraph

class SQLFormatSource extends TaintTracking::TaintSource {
  SQLFormatSource() {
    exists(CallNode call |
      call.getCode().regexpMatch("\\.\\.\\.\\s*%\\.\\.\\.") and
      this = call.getNode()
    )
    or
    exists(CallNode call |
      call.getMethodFullName().regexpMatch(".*\\.format") and
      this = call.getNode()
    )
    or
    exists(Literal literal |
      literal.getCode().matches("%f\"%") and
      this = literal.getNode()
    )
  }
}

class SQLExecuteSink extends TaintTracking::TaintSink {
  SQLExecuteSink() {
    exists(CallNode call |
      call.getMethodName() = "execute" and
      this = call.getArgument(0).getNode()
    )
  }
}

class SQLTaintConfig extends TaintTracking::Configuration {
  SQLTaintConfig() { this = "SQLTaintConfig" }

  override predicate isSource(TaintTracking::Source source) {
    source instanceof SQLFormatSource
  }

  override predicate isSink(TaintTracking::Sink sink) {
    sink instanceof SQLExecuteSink
  }
}

from SQLTaintConfig cfg, SQLFormatSource source, SQLExecuteSink sink
where cfg.hasFlow(source, sink)
select sink.getNode(), "Detected possible formatted SQL query. Use parameterized queries instead."