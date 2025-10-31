/**
 * @name MySQL SQL Injection from Lambda event
 * @description Detected SQL statement that is tainted by `event` object.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.3
 * @precision high
 * @id python/mysql-sqli
 * @tags security
 *       python
 *       aws-lambda
 *       mysql
 * @security-severity 8.3
 * @references https://dev.mysql.com/doc/connector-python/en/connector-python-api-mysqlcursor-execute.html,
 *             https://dev.mysql.com/doc/connector-python/en/connector-python-api-mysqlcursor-executemany.html
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.Concepts

class LambdaEventSource extends DataFlow::Node {
  LambdaEventSource() {
    exists(Function f, Parameter p |
      p.getParent() = f and
      p.getName() = "event" and
      f.getName().matches("%handler%") and
      this.asParameter() = p
    )
  }
}

class MySqlExecuteCall extends DataFlow::Node {
  MySqlExecuteCall() {
    exists(Call call |
      call.getCallee().getQualifiedName().matches("%mysql.cursors%.execute") or
      call.getCallee().getQualifiedName().matches("%mysql.cursors%.executemany") and
      this = call.getArg(0)
    )
  }
}

class MySqlSQLIConfig extends TaintTracking::Configuration {
  MySqlSQLIConfig() { this = "MySqlSQLI" }

  override predicate isSource(DataFlow::Node source) { source instanceof LambdaEventSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof MySqlExecuteCall }
}

from MySqlSQLIConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized."