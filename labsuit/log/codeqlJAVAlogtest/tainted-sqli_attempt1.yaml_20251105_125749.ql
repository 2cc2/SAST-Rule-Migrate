/**
 * @name Tainted SQL Injection
 * @description Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if variables in the SQL statement are not properly sanitized.
 * @kind taint
 * @problem.severity Warning
 * @security-severity 8.8
 * @precision medium
 * @id java/tainted-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 *       technology/sql
 *       technology/java
 *       technology/aws-lambda
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.AWSLambda

class EventSource extends MethodInputParameter {
  EventSource() {
    (
      // Case 1: (..., $EVENT, Context)
      this.getName() = "$EVENT" and
      getMethod().getSignature().matches("\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)")
    )
    or
    (
      // Case 2: (InputStream, OutputStream, $EVENT, Context)
      this.getName() = "$EVENT" and
      getMethod().getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)")
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      (
        // SQL Statement methods
        ma.getMethod().hasName(["execute", "executeQuery", "executeUpdate"]) and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", ["Statement", "PreparedStatement", "CallableStatement"])
      )
      or
      (
        // JdbcTemplate methods
        ma.getMethod().hasName(["batchUpdate", "queryForObject", "queryForMap"]) and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate")
      )
      or
      (
        ma.getMethod().hasName("prepareStatement") and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Connection")
      )
      |
      this.asExpr() = ma.getArgument(0) and
      ma.getArgument(0).toString().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)")
    )
  }
}

class TaintedSqlInjectionConfig extends TaintTracking::Configuration {
  TaintedSqlInjectionConfig() { this = "TaintedSqlInjectionConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof EventSource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(ParameterizedType pt, Callable c, int i |
      pred.asParameter() = c.getParameter(i) and
      succ.asExpr() = c.getParameter(i).getAnAccess()
    )
  }
}

from TaintedSqlInjectionConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential SQL injection from AWS Lambda $EVENT object to SQL execution"