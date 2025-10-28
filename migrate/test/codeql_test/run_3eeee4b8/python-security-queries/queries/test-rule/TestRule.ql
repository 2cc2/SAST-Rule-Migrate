/**
 * @id formatted-sql-query
 * @kind problem
 * @severity warning
 * @name Detected possible formatted SQL query
 * @description Using string formatting for SQL queries may lead to SQL injection vulnerabilities. Use parameterized queries instead.
 */

import python
import DataFlow::PathGraph

class StringFormatCall extends DataFlow::Node {
  StringFormatCall() {
    exists(MethodCall call |
      exists(RegexPattern re |
        re = "^.*(%|format|f-string)$" and
        call.getTarget().getName().regexpMatches(re) and
        this.asExpr() = call.getExpr()
      )
    )
  }
}

class SqlExecuteCall extends DataFlow::Node {
  SqlExecuteCall() {
    exists(MethodCall call |
      call.getTarget().getName() = "execute" and
      this.asExpr() = call.getArgument(0)
    )
  }
}

query predicate isSource(DataFlow::Node source) {
  source instanceof StringFormatCall
}

query predicate isSink(DataFlow::Node sink) {
  sink instanceof SqlExecuteCall
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where DataFlow::flowPath(source, sink)
select sink.getNode(), "Detected possible formatted SQL query. Use parameterized queries instead.",
  source.getNode(), "String formatting operation here",
  sink.getNode(), "SQL execution found here"