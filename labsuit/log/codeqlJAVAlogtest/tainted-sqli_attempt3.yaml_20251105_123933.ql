/**
 * @name Tainted SQL injection in AWS Lambda
 * @description Detects SQL statements that are tainted by $EVENT object, which could lead to SQL injection
 * @kind path-problem
 * @problem.severity warning
 * @id java/tainted-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.aws.AWSLambda
import DataFlow::PathGraph

class LambdaEventSource extends DataFlow::Expr {
  LambdaEventSource() {
    exists(Method m, Parameter p |
      m.getDeclaringType() instanceof AWSLambdaHandler and
      (
        (
          m.getSignature().matches("(\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\))") and
          p.getName() = "$EVENT"
        )
        or
        (
          m.getSignature().matches("(\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\))") and
          p.getName() = "$EVENT"
        )
      ) and
      p = this.asParameter()
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
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
      ma.getArgument(0).getStringValue().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class TaintedSqlConfig extends DataFlow::TaintTrackingConfiguration {
  TaintedSqlConfig() { this = "TaintedSqlConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof LambdaEventSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlSink
  }
}

from TaintedSqlConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected SQL statement that is tainted by $EVENT object. " +
  "This could lead to SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use parameterized SQL queries or properly sanitize user input instead."