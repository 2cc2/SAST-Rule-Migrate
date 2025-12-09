/**
 * @id tainted-sqli
 * @kind taint
 * @severity Warning
 * @name Tainted SQL injection vulnerability
 * @description Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if variables in the SQL statement are not properly sanitized.
 * @tags security
 *       sql
 *       java
 *       aws-lambda
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.AWSLambda

class EventSource extends DataFlow::Node {
  EventSource() {
    exists(Method m, Parameter p |
      m.getAParameter() = p and
      (
        // First case: ($TYPE, Context) signature
        (
          m.getSignature().matches("\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
          p.getName() = "$EVENT"
        )
        or
        // Second case: (InputStream, OutputStream, Context) signature
        (
          m.getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
          p.getName() = "$EVENT"
        )
      ) and
      this.asParameter() = p
    )
  }
}

class SinkCall extends DataFlow::Node {
  SinkCall() {
    exists(MethodAccess ma, string methodName |
      ma.getMethod().hasName([
        "execute", "executeQuery", "executeUpdate", "batchUpdate", 
        "queryForObject", "queryForMap", "prepareStatement"
      ]) and
      (
        ma.getQualifier().getType().hasQualifiedName([
          "java.sql", "Statement",
          "java.sql", "PreparedStatement",
          "java.sql", "CallableStatement",
          "org.springframework.jdbc.core", "JdbcTemplate",
          "java.sql", "Connection",
          "org.springframework.jdbc.support.rowset", "SqlRowSet"
        ]) or
        ma.getMethod().getDeclaringType().hasQualifiedName([
          "java.sql", "Statement",
          "java.sql", "PreparedStatement",
          "java.sql", "CallableStatement",
          "org.springframework.jdbc.core", "JdbcTemplate",
          "java.sql", "Connection",
          "org.springframework.jdbc.support.rowset", "SqlRowSet"
        ])
      ) and
      ma.getArgument(0).getStringValue().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class TaintedSqlQuery extends TaintTracking::Configuration {
  TaintedSqlQuery() { this = "Tainted SQL query" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof EventSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SinkCall
  }
}