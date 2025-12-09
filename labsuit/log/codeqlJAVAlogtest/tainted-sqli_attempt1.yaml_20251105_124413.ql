/**
 * @name Tainted SQL Injection in AWS Lambda
 * @description Detected SQL statement that is tainted by `$EVENT` object.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision medium
 * @id java/tainted-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 *       technology/sql
 *       technology/java
 *       technology/aws-lambda
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Spring

class LambdaEventSource extends MethodAccess {
  LambdaEventSource() {
    (
      // Case 1: (APIGatewayProxyRequestEvent/$EVENT, Context)
      (
        this.getMethod().getDeclaringType().getASourceSupertype*().hasQualifiedName("com.amazonaws.services.lambda.runtime", "RequestHandler") and
        this.getMethod().getSignature().matches("\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
        this.getArgument(0).getName() = "$EVENT"
      )
      or
      // Case 2: (InputStream, OutputStream, Context)
      (
        this.getMethod().getDeclaringType().getASourceSupertype*().hasQualifiedName("com.amazonaws.services.lambda.runtime", "RequestStreamHandler") and
        this.getMethod().getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
        this.getArgument(0).getName() = "$EVENT"
      )
    )
  }
}

class SqlSink extends MethodAccess {
  SqlSink() {
    getTarget().hasQualifiedName(
      ["java.sql.Statement", "java.sql.PreparedStatement", "java.sql.CallableStatement", 
       "org.springframework.jdbc.core.JdbcTemplate", "java.sql.Connection",
       "org.springframework.jdbc.support.rowset.SqlRowSet"],
      ["execute", "executeQuery", "executeUpdate", "batchUpdate", 
       "queryForObject", "queryForMap", "prepareStatement"]
    ) and
    (
      not this.getArgument(0).isConstant() and
      this.getArgument(0).getValue().toString().matches("(?i)(^SELECT.* | ^INSERT.* | ^UPDATE.*)")
    )
  }
}

class TaintedSqlFlowConfig extends TaintTracking::Configuration {
  TaintedSqlFlowConfig() { this = "TaintedSqlFlowConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(LambdaEventSource la | source.asParameter() = la.getArgument(0))
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SqlSink sql | sink.asExpr() = sql.getArgument(0))
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Handle argument-to-parameter propagation
    exists(MethodAccess ma, int argIndex |
      pred.asExpr() = ma.getArgument(argIndex) and
      succ.asParameter() = ma.getMethod().getParameter(argIndex)
    )
  }
}

from TaintedSqlFlowConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Detected SQL statement that is tainted by $EVENT object. $@",
  source, "User input from here"