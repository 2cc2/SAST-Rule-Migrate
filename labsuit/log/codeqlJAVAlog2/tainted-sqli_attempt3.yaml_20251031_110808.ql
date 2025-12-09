/**
 * @name Tainted SQL Injection in AWS Lambda
 * @description Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection.
 * @kind problem
 * @id java/tainted-sqli
 * @severity warning
 * @tags security
 *       sql
 *       aws-lambda
 *       cwe-89
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.aws.Lambda

class LambdaEventSource extends DataFlow::Node {
  LambdaEventSource() {
    exists(Method m, Parameter p |
      m.getAPackage().getName().matches("%aws.lambda%") and
      (
        (m.getSignature().matches("(%$TYPE%,com.amazonaws.services.lambda.runtime.Context)") and
          p.getName() = "$EVENT")
        or
        (m.getSignature().matches("(InputStream%,OutputStream%,com.amazonaws.services.lambda.runtime.Context)") and
          p.getName() = "$EVENT")
      ) and
      this.asParameter() = p
    )
  }
}

class SQLSink extends DataFlow::Node {
  SQLSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") or
       ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
       ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "CallableStatement") or
       ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") or
       ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Connection") or
       ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.support.rowset", "SqlRowSet")) and
      (ma.getMethod().getName() = "execute" or
       ma.getMethod().getName() = "executeQuery" or
       ma.getMethod().getName() = "executeUpdate" or
       ma.getMethod().getName() = "batchUpdate" or
       ma.getMethod().getName() = "queryForObject" or
       ma.getMethod().getName() = "queryForMap" or
       ma.getMethod().getName() = "prepareStatement") and
      ma.getArgument(0).getStringValue().matches("%SELECT%|%INSERT%|%UPDATE%") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class TaintedSQLFlowConfiguration extends TaintTracking::Configuration {
  TaintedSQLFlowConfiguration() { this = "TaintedSQLFlowConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof LambdaEventSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SQLSink }
}

from TaintedSQLFlowConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink,
  "Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection.",
  source, "User input originates from here"