/**
 * @name Tainted SQL query from AWS Lambda event
 * @description Detects SQL statements that are tainted by `$EVENT` object,
 *              which could lead to SQL injection if variables are not properly sanitized.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id java/tainted-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 *       
 */

import java
import DataFlow::PathGraph
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.aws.AWSLambda

class EventSource extends DataFlow::Expr {
  EventSource() {
    exists(Method m, Parameter p |
      m = p.getMethod() and
      p.getName() = "$EVENT" and
      (
        m.getSignature().matches("\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") or
        m.getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)")
      ) and
      this = p.getAnAccess()
    )
  }
}

class SqlSink extends DataFlow::Expr {
  SqlSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["execute", "executeQuery", "executeUpdate", "batchUpdate", 
                            "queryForObject", "queryForMap", "prepareStatement"]) and
      ma.getMethod().getDeclaringType().hasQualifiedName(["java.sql", "org.springframework.jdbc.core"], 
                        ["Statement", "PreparedStatement", "CallableStatement", "JdbcTemplate", 
                         "Connection", "SqlRowSet"]) and
      ma.getArgument(0).toString().matches("(?i)(^SELECT.* | ^INSERT.* | ^UPDATE.*)") and
      this = ma.getArgument(0)
    )
  }
}

class TaintedSqlQueryConfig extends TaintTracking::Configuration {
  TaintedSqlQueryConfig() { this = "TaintedSqlQueryConfig" }

  override predicate isSource(DataFlow::Node source) { source.asExpr() instanceof EventSource }

  override predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof SqlSink }
}

from TaintedSqlQueryConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), 
  "Detected SQL statement that is tainted by `$EVENT` object. " +
  "This could lead to SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use parameterized SQL queries or properly sanitize user input instead.", 
  source.getNode(), "User input from $EVENT"