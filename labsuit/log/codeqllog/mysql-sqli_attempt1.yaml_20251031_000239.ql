/**
 * @name MySQL SQL Injection from AWS Lambda Event
 * @description Detected SQL statement that is tainted by `event` object. 
 *              This could lead to SQL injection if the variable is user-controlled
 *              and not properly sanitized.
 * @id mysql-sqli
 * @kind path-problem
 * @problem.severity warning
 * @tags security
 *       python
 *       aws-lambda
 *       mysql
 * @security-severity 7.5
 */

import python
import DataFlow::PathGraph

class LambdaEventHandler extends DataFlow::Node {
  LambdaEventHandler() {
    exists(Function f, Parameter p |
      f.getName() = "lambda_handler" and
      p.getFunction() = f and
      p.getName() = "event"
    )
  }
}

class MySqlExecuteCall extends DataFlow::Node {
  MySqlExecuteCall() {
    exists(Call call |
      call.getTarget().getName() = "execute" or
      call.getTarget().getName() = "executemany" and
      call.getTarget()
          .getQualifiedName()
          .matches("mysql.cursors.%")
      and call = this.asExpr()
    )
  }
}

query predicate isSource(DataFlow::Node source) { source instanceof LambdaEventHandler }
query predicate isSink(DataFlow::Node sink) { sink instanceof MySqlExecuteCall }

from DataFlow::PathNode source, DataFlow::PathNode sink
where DataFlow::flowPath(source, sink)
select sink.getNode(), 
  "Potential SQL Injection from AWS Lambda event object to MySQL execute call",
  source.getNode(), "User input flows here",
  sink.getNode(), "SQL query execution"