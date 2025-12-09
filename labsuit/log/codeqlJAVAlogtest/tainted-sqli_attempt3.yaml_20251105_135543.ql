/**
 * @name Tainted SQL Injection
 * @description Detected SQL statement that is tainted by $EVENT object.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision medium
 * @id java/tainted-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       owasp-a01:2017
 *       owasp-a03:2021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class EventSource extends DataFlow::Node {
  EventSource() {
    exists(Method m, Parameter p |
      m.getAParameter() = p and
      (
        (p.getName() = "$EVENT" and
         m.getSignature().matches("\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)")) or
        (p.getName() = "$EVENT" and
         m.getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)"))
      ) and
      this.asParameter() = p
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(Method m, Expr arg |
      m.getName() in ["execute", "executeQuery", "executeUpdate", "batchUpdate", 
                    "queryForObject", "queryForMap", "prepareStatement"] and
      m.getDeclaringType().getQualifiedName() in ["java.sql.Statement", "java.sql.PreparedStatement", "java.sql.CallableStatement",
                  "org.springframework.jdbc.core.JdbcTemplate", "java.sql.Connection",
                  "org.springframework.jdbc.support.rowset.SqlRowSet"] and
      arg = m.getACall().getArgument(0) and
      arg.getStringValue().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)") and
      this.asExpr() = arg
    )
  }
}

class TaintedSqlFlowConfiguration extends TaintTracking::Configuration {
  TaintedSqlFlowConfiguration() { this = "TaintedSqlFlow" }

  override predicate isSource(DataFlow::Node source) { source instanceof EventSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Parameter p, Method m |
      pred.asParameter() = p and
      p = m.getAParameter() and
      exists(m.getACall().getArgument(0) arg |
        succ.asExpr() = arg
      )
    )
  }
}

from TaintedSqlFlowConfiguration config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Detected SQL statement that is tainted by $EVENT object. This could lead to SQL " +
  "injection if variables in the SQL statement are not properly sanitized. Use parameterized SQL " +
  "queries or properly sanitize user input instead."