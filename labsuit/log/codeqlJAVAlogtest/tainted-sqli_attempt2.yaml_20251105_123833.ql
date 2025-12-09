/**
 * @name Tainted SQL Injection via AWS Lambda Event
 * @description Detected SQL statement that is tainted by $EVENT object.
 * @kind problem
 * @id java/tainted-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01
 *       external/owasp/a03
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class LambdaEventSource extends DataFlow::Node {
  LambdaEventSource() {
    exists(Method m, Parameter p |
      m.getNumberOfParameters() >= 1 and
      p = m.getParameter(0) and
      (
        (
          m.getSignature().matches(".*\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
          p.getName() = "$EVENT"
        )
        or
        (
          m.getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
          p.getName() = "$EVENT"
        )
      ) and
      this.asParameter() = p
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(Call call |
      (
        call.getCallee().getDeclaringType().hasQualifiedName("java.sql", "Statement") or
        call.getCallee().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
        call.getCallee().getDeclaringType().hasQualifiedName("java.sql", "CallableStatement") or
        call.getCallee().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") or
        call.getCallee().getDeclaringType().hasQualifiedName("java.sql", "Connection") or
        call.getCallee().getDeclaringType().hasQualifiedName("org.springframework.jdbc.support.rowset", "SqlRowSet")
      ) and
      (
        call.getCallee().getName() = "execute" or
        call.getCallee().getName() = "executeQuery" or
        call.getCallee().getName() = "executeUpdate" or
        call.getCallee().getName() = "batchUpdate" or
        call.getCallee().getName() = "queryForObject" or
        call.getCallee().getName() = "queryForMap" or
        call.getCallee().getName() = "prepareStatement"
      ) and
      call.getArgument(0).toString().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)") and
      this.asExpr() = call.getArgument(0)
    )
  }
}

class TaintedSQLIConfig extends TaintTracking::Configuration {
  TaintedSQLIConfig() { this = "TaintedSQLIConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof LambdaEventSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }
}

from TaintedSQLIConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Detected SQL statement that is tainted by $EVENT object. This could lead to SQL injection if " +
  "variables in the SQL statement are not properly sanitized. Use parameterized SQL queries or properly " +
  "sanitize user input instead."