/**
 * @name Formatted SQL Query Detection
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind problem
 * @id formatted-sql-query
 * @problem.severity warning
 * @security-severity 7.5
 * @precision low
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.dataflow.DataFlow

class SQLFormatPercent extends DataFlow::CallNode {
  SQLFormatPercent() {
    this.getCode().regexpMatch("\\\\.\\\\.\\\\.\\\\s*%\\\\.\\\\.\\\\.'")
  }
}

class SQLFormatFunction extends DataFlow::CallNode {
  SQLFormatFunction() {
    this.getMethodFullName().regexpMatch(".*\\\\.format")
  }
}

class SQLFormatFString extends DataFlow::Literal::String {
  SQLFormatFString() {
    this.getCode().indexOf("f\"") >= 0
  }
}

class SQLExecutionSink extends DataFlow::CallNode {
  SQLExecutionSink() {
    this.getMethodName() = "execute" and
    this.getArgument(0).getAnArg() = _
  }
}

predicate isSource(Node node) {
  exists(SQLFormatPercent s | node = s) or
  exists(SQLFormatFunction s | node = s) or
  exists(SQLFormatFString s | node = s)
}

predicate isSink(Node node) {
  exists(SQLExecutionSink s | node = s)
}

query predicate sqlInjectionFlow(DataFlow::Node source, DataFlow::Node sink) {
  exists(DataFlow::PathNode src, DataFlow::PathNode snk |
    DataFlow::localFlow(src, snk) and
    isSource(src.getNode()) and
    isSink(snk.getNode())
  )
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where sqlInjectionFlow(source, sink)
select sink.getNode(), 
  "Detected possible formatted SQL query. Use parameterized queries instead.",
  source.getNode(), "This is user-controlled input"