/**
 * @name MySQL SQL Injection from Event Parameter
 * @description Detects SQL statement that is tainted by event object
 * @id mysql-sqli
 * @kind path-problem
 * @problem.severity warning
 */

import python
import semmle.python.dataflow.TaintTracking
import semmle.python.dataflow.TaintTracking::PathGraph

class EventSource extends TaintTracking::Source {
  EventSource() { 
    exists(Function f, Parameter p |
      f.getParameter(0) = p and
      p.getName() = "event" and
      f.getName().matches("%HANDLER%")
    )
  }
}

class MySqlExecuteSink extends TaintTracking::Sink {
  MySqlExecuteSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("execute%") and
      ma.getQualifier().getType().getName() = "Cursor"
    )
  }
}

class MysqlSqliConfig extends TaintTracking::Configuration {
  MysqlSqliConfig() { this = "MysqlSqliConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asParameter().getFunction().getParameter(0).getName() = "event"
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(MethodAccess ma |
      ma.getMethod().getName().matches("execute%") and
      ma.getQualifier().getType().getName() = "Cursor"
    ).getAnArgument()
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, MysqlSqliConfig cfg
where cfg.hasFlowPath(source, sink)
select sink, "Potential SQL injection from event parameter to MySQL query execution"