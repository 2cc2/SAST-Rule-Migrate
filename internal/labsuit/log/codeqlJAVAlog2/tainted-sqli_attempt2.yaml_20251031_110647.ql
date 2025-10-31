/**
 * @name Tainted SQL Injection in AWS Lambda
 * @description Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @id java/tainted-sqli
 * @tags security
 *       cwe: "89"
 *       owasp: "A01:2017"
 *       owasp: "A03:2021"
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow

predicate isSource(Parameter p) {
  exists(Method m | 
    m.getAParameter() = p and
    (
      (m.getSignature().matches("\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
       p.getName() = "$EVENT") 
      or
      (m.getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
       p.getName() = "$EVENT")
    )
  )
}

class SQLSink extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma, string stmtType, string stmtMethod |
      // Check for JDBC statement types
      stmtType in [
        "java.sql.Statement", 
        "java.sql.PreparedStatement", 
        "java.sql.CallableStatement",
        "org.springframework.jdbc.core.JdbcTemplate",
        "java.sql.Connection",
        "org.springframework.jdbc.support.rowset.SqlRowSet"
      ] and
      stmtMethod in [
        "execute", "executeQuery", "executeUpdate", "batchUpdate",
        "queryForObject", "queryForMap", "prepareStatement"
      ] and
      ma.getMethod().getDeclaringType().hasQualifiedName(stmtType) and
      ma.getMethod().getName() = stmtMethod and
      // Check first sql argument is a query string
      ma.getArgument(0).toString().matches("(?i)(^SELECT.* | ^INSERT.* | ^UPDATE.*)") and
      pred.asExpr() = ma.getArgument(0) and
      succ.asExpr() = ma.getArgument(0)
    )
  }
}

from Parameter source, DataFlow::Node sink
where
  isSource(source) and
  TaintTracking::localTaint(DataFlow::parameterNode(source), sink)
select sink, "Detected SQL statement that is tainted by `$EVENT` object. " +
  "This could lead to SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use parameterized SQL queries or properly sanitize user input instead."