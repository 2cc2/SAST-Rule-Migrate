/**
 * @name MySQL SQL Injection via Lambda Event
 * @description Detected SQL statement that is tainted by `event` object. 
 * @id mysql-sqli
 * @kind path-problem
 * @problem.severity warning
 * @tags security
 *       python
 *       aws-lambda
 *       mysql
 * @security-severity 8.0
 */

import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

class LambdaEventSource extends DataFlow::Node {
  LambdaEventSource() {
    exists(Parameter p |
      p.getName() = "event" and
      exists(Function f |
        p.getFunction() = f and
        f.getName().matches("%HANDLER%")
      ) and
      this = p
    )
  }
}

class MySqlExecuteCall extends DataFlow::Node {
  MySqlExecuteCall() {
    exists(Call call |
      call.getTarget().getName() = "execute" and
      call.getTarget().getDeclaringType().getAPackageName().matches("%mysql.connector.cursor%") and
      this = call.getArgument(0)
    ) or
    exists(Call call |
      call.getTarget().getName() = "executemany" and
      call.getTarget().getDeclaringType().getAPackageName().matches("%mysql.connector.cursor%") and
      this = call.getArgument(0)
    )
  }
}

class MySqlTaintConfig extends TaintTracking::Configuration {
  MySqlTaintConfig() { this = "MySqlTaintConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof LambdaEventSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof MySqlExecuteCall }
}

from MySqlTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, 
  "Detected SQL statement that is tainted by `event` object. This could lead to SQL injection.", 
  source, sink,
  "AWS Lambda event parameter is used in MySQL query without sanitization"