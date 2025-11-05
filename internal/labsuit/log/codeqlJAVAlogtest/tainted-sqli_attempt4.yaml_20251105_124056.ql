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
import DataFlow::PathGraph
import DataFlow::TaintTracking

class LambdaEventSource extends DataFlow::Node {
  LambdaEventSource() {
    exists(Method m, Parameter p |
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
    exists(Method m, Expr arg |
      (m.getDeclaringType().hasQualifiedName("java.sql", "Statement") or
       m.getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
       m.getDeclaringType().hasQualifiedName("java.sql", "CallableStatement") or
       m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") or
       m.getDeclaringType().hasQualifiedName("java.sql", "Connection") or
       m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.support.rowset", "SqlRowSet")) and
      (m.getName() = "execute" or
       m.getName() = "executeQuery" or
       m.getName() = "executeUpdate" or
       m.getName() = "batchUpdate" or
       m.getName() = "queryForObject" or
       m.getName() = "queryForMap" or
       m.getName() = "prepareStatement") and
      arg = m.getACall().getArgument(0) and
      arg.getStringValue().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)") and
      this.asExpr() = arg
    )
  }
}

class TaintedSqlConfig extends TaintTracking::Configuration {
  TaintedSqlConfig() { this = "TaintedSqlConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof LambdaEventSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlSink
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedSqlConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected SQL statement that is tainted by $EVENT object. " +
  "This could lead to SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use parameterized SQL queries or properly sanitize user input instead."