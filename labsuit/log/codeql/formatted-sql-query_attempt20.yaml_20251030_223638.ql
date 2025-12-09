/**
 * @name Formatted SQL Query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind path-problem
 * @problem.severity warning
 * @id python/security/formatted-sql-query
 * @tags security
 *       external/cwe/cwe-089
 *       external/oavsp/a01:2017
 *       external/oavsp/a03:2021
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class SQLFormatSource extends DataFlow::Node {
  SQLFormatSource() {
    exists(string pattern |
      // Match percentage format patterns (e.g. "WHERE name = %s")
      pattern = "%.%.%.\\s*%.%.%." and
      this.asExpr().getLocation().getFile().getContent().matches(pattern)
    )
    or
    exists(string methodName |
      // Match .format() method calls
      methodName = ".*\\.format" and
      this.asExpr().(CallNode).getCallee().getQualifiedName().matches(methodName)
    )
    or
    exists(string content |
      // Match f-string literals
      content = "f\\\"" and
      this.asExpr().getStringValue().matches(content)
    )
  }
}

class SQLExecuteSink extends DataFlow::Node {
  SQLExecuteSink() { 
    exists(string methodName |
      methodName = "execute" and
      this.asExpr().(CallNode).getCalleeName() = methodName and
      this = this.asExpr().(CallNode).getArgument(0)
    )
  }
}

class SQLTaintConfig extends TaintTracking::Configuration {
  SQLTaintConfig() { this = "SQLTaintConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof SQLFormatSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SQLExecuteSink }
}

from SQLTaintConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected possible formatted SQL query. Use parameterized queries instead."