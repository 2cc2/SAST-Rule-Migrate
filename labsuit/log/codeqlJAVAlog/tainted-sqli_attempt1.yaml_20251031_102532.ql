/**
 * @name Tainted SQL injection in AWS Lambda
 * @description Detected SQL statement that is tainted by `$EVENT` object. This could lead 
 *              to SQL injection if variables in the SQL statement are not properly sanitized. 
 *              Use parameterized SQL queries or properly sanitize user input instead.
 * @id tainted-sqli
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       java
 *       sql
 *       aws-lambda
 * @cwe 89
 * @owasp A01:2017 - Injection
 * @owasp A03:2021 - Injection
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.AWSLambda

class EventSource extends DataFlow::Node {
  EventSource() {
    (exists(Method m | m.getAParameter().getName() = "$EVENT" |
      (m.getSignature().matches("\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") 
      or m.getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)"))
      and this.asParameter() = m.getAParameter()
    ))
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() in ["execute", "executeQuery", "executeUpdate", "batchUpdate", 
                                   "queryForObject", "queryForMap", "prepareStatement"] and
      ma.getMethod().getDeclaringType().getASupertype*().getQualifiedName() in 
        ["java.sql.Statement", "java.sql.PreparedStatement", "java.sql.CallableStatement",
         "org.springframework.jdbc.core.JdbcTemplate", "java.sql.Connection",
         "org.springframework.jdbc.support.rowset.SqlRowSet"]) and
      ma.getArgument(0).getText().matches("(?i)(^SELECT.* | ^INSERT.* | ^UPDATE.*)") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class EventToSqlFlow extends TaintTracking::Configuration {
  EventToSqlFlow() { this = "EventToSqlFlow" }

  override predicate isSource(DataFlow::Node source) { source instanceof EventSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Propagation through argument passing
    exists(MethodAccess ma, int argIdx |
      ma.getArgument(argIdx) = node1.asExpr() and
      node2.asParameter() = ma.getMethod().getParameter(argIdx)
    )
  }
}

from EventToSqlFlow config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential SQL injection from AWS Lambda $EVENT parameter to SQL execution"