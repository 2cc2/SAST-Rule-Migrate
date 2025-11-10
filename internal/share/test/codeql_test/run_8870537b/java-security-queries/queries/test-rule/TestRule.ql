/**
 * @name Tainted SQL from Lambda Event
 * @description Detected SQL statement that is tainted by `$EVENT` object. 
 *              This could lead to SQL injection if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @id java/tainted-sqli-from-lambda
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017  
 *       external/owasp/a03:2021
 *       technology/sql
 *       technology/aws-lambda
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.SQL

class LambdaEventSource extends DataFlow::Node {
  LambdaEventSource() {
    exists(Method m, Parameter p |
      (m.getSignature().matches("\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") or
       m.getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)")) and
      p.getName() = "$EVENT" and
      p = this.asParameter()
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().hasName([
        "java.sql.Statement", 
        "java.sql.PreparedStatement",
        "java.sql.CallableStatement",
        "org.springframework.jdbc.core.JdbcTemplate",
        "java.sql.Connection",
        "org.springframework.jdbc.support.rowset.SqlRowSet"
      ]) and
      ma.getMethod().hasName([
        "execute", "executeQuery", "executeUpdate", "batchUpdate",
        "queryForObject", "queryForMap", "prepareStatement"
      ])) and
      ma.getArgument(0).getStringValue().regexpMatch("(?i)(^SELECT.* | ^INSERT.* | ^UPDATE.*)") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class TaintedSqlFlowConfig extends TaintTracking::Configuration {
  TaintedSqlFlowConfig() { this = "TaintedSqlFromLambdaEvent" }

  override predicate isSource(DataFlow::Node source) { source instanceof LambdaEventSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlExecutionSink }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma | 
      ma.getArgument(0) = pred.asExpr() and
      ma.getMethod().getParameter(0).getType() = ma.getArgument(0).getType() and
      succ.asParameter() = ma.getMethod().getParameter(0)
    )
  }
}

from TaintedSqlFlowConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected SQL statement that is tainted by `$EVENT` object", source.getNode(),
  "This could lead to SQL injection if variables are not properly sanitized"