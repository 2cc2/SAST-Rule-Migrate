/**
 * @name Tainted SQL Injection in AWS Lambda
 * @description Detected SQL statement that is tainted by $EVENT object. This could lead to SQL injection if variables in the SQL statement are not properly sanitized.
 * @kind problem
 * @severity Warning
 * @id java/tainted-sqli
 * @tags security
 *       sql
 *       aws-lambda
 *       cwe
 *       owasp
 * @security-severity 8.0
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.PathGraph
import semmle.code.java.Parameter

class LambdaEventSource extends Parameter {
  LambdaEventSource() {
    exists(Method m |
      (m.getSignature().matches("\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") or
       m.getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)")) and
      this.getQualifiedName() = "$EVENT" and
      this.getDeclaringCallable() = m
    )
  }
}

class SqlSink extends MethodCall {
  SqlSink() {
    exists(Method m | 
      m.getName().matches("execute|executeQuery|executeUpdate|batchUpdate|queryForObject|queryForMap|prepareStatement") and
      (m.getDeclaringType().hasQualifiedName("java.sql", "Statement") or
       m.getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
       m.getDeclaringType().hasQualifiedName("java.sql", "CallableStatement") or
       m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") or
       m.getDeclaringType().hasQualifiedName("java.sql", "Connection") or
       m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.support.rowset", "SqlRowSet")) and
      this.getMethod() = m and
      this.getArgument(0).toString().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)")
    )
  }
}

class TaintedSQLConfig extends TaintTracking::TaintTrackingConfiguration {
  TaintedSQLConfig() { this = "TaintedSQLConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asParameter() instanceof LambdaEventSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SqlSink sql | sink.asExpr() = sql.getArgument(0))
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodCall call |
      call.getArgument(0) = node1.asExpr() and
      call.getMethod().getAParameter() = node2.asParameter()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedSQLConfig config
where config.hasFlowPath(source, sink)
select sink, 
  "Detected SQL statement that is tainted by $EVENT object. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use parameterized SQL queries or properly sanitize user input instead.",
  source, sink,
  "Potential SQL injection vulnerability"