/**
 * @name Tainted SQL Injection via AWS Lambda Event Object
 * @description Detected SQL statement that is tainted by `$EVENT` object
 * @kind problem
 * @id java/tainted-sqli
 * @severity warning
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.AWSLambda
import DataFlow::PathGraph

class EventSource extends DataFlow::Node {
  EventSource() {
    exists(Method m, Parameter p |
      m.getAParameter() = p and
      (
        (
          m.getSignature().matches("\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
          p.hasName("$EVENT")
        )
        or
        (
          m.getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
          p.hasName("$EVENT")
        )
      ) and
      this.asParameter() = p
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "CallableStatement") or
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Connection") or
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.support.rowset", "SqlRowSet") and
      ma.getMethod().hasName("execute") or
      ma.getMethod().hasName("executeQuery") or
      ma.getMethod().hasName("executeUpdate") or
      ma.getMethod().hasName("batchUpdate") or
      ma.getMethod().hasName("queryForObject") or
      ma.getMethod().hasName("queryForMap") or
      ma.getMethod().hasName("prepareStatement") and
      ma.getArgument(0).toString().matches("(?i)(^SELECT.* | ^INSERT.* | ^UPDATE.*)") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class TaintedSqlConfiguration extends TaintTracking::Configuration {
  TaintedSqlConfiguration() { this = "TaintedSqlConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof EventSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma | ma.getAnArgument() = pred.asExpr() and ma.getArgument(0) = succ.asExpr())
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedSqlConfiguration conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), 
  "Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if " +
  "variables in the SQL statement are not properly sanitized. Use parameterized SQL queries or " +
  "properly sanitize user input instead.",
  source.getNode(), "Tainted source here"