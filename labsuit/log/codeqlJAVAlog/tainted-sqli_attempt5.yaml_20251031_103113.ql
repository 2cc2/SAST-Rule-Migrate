/**
 * @id tainted-sqli
 * @kind path-problem
 * @name Tainted SQL Injection in AWS Lambda
 * @description Detected SQL statement that is tainted by `$EVENT` object. This could lead
 *              to SQL injection if variables in the SQL statement are not properly sanitized.
 *              Use parameterized SQL queries or properly sanitize user input instead.
 * @severity warning
 * @precision medium
 * @security-severity 8.8
 * @tags security
 *       sql
 *       java
 *       aws-lambda
 * @problem.severity warning
 * @security-severity 8.8
 * @kind path-problem
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.aws.AWSLambda

class LambdaEventHandler extends DataFlow::Node {
  LambdaEventHandler() {
    exists(Method m, Parameter p |
      m = p.getMethod() and
      (
        (m.getSignature().matches("\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
         p.getName() = "$EVENT")
        or
        (m.getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
         p.getName() = "$EVENT")
      ) and
      this.asParameter() = p
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
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
      ma.getArgument(0).toString().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class TaintedSqlInjectionConfig extends TaintTracking::Configuration {
  TaintedSqlInjectionConfig() { this = "TaintedSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof LambdaEventHandler
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(DataFlow::ParameterNode param, DataFlow::ArgumentNode arg |
      node1.asParameter() = param and
      node2.asArgument() = arg and
      arg.getCall().getArgumentPosition(arg) = param.getIndex()
    )
  }
}

from TaintedSqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected SQL statement that is tainted by `$EVENT` object. " +
  "This could lead to SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use parameterized SQL queries or properly sanitize user input instead."