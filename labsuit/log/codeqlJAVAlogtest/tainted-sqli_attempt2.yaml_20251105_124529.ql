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
import semmle.code.java.dataflow.DataFlow

class LambdaEventSource extends DataFlow::Expr {
  LambdaEventSource() {
    exists(Method m |
      (
        // Case 1: (APIGatewayProxyRequestEvent/$EVENT, Context)
        (
          m.getDeclaringType().getASourceSupertype*().hasQualifiedName("com.amazonaws.services.lambda.runtime", "RequestHandler") and
          m.getSignature().matches("\\(\\$TYPE.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
          this = m.getParameter(0).getAnAccess() and
          m.getParameter(0).getName() = "$EVENT"
        )
        or
        // Case 2: (InputStream, OutputStream, Context)
        (
          m.getDeclaringType().getASourceSupertype*().hasQualifiedName("com.amazonaws.services.lambda.runtime", "RequestStreamHandler") and
          m.getSignature().matches("\\(InputStream.*,OutputStream.*,com\\.amazonaws\\.services\\.lambda\\.runtime\\.Context\\)") and
          this = m.getParameter(0).getAnAccess() and
          m.getParameter(0).getName() = "$EVENT"
        )
      )
    )
  }
}

class SqlSink extends DataFlow::Expr {
  SqlSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName(
        ["java.sql.Statement", "java.sql.PreparedStatement", "java.sql.CallableStatement", 
         "org.springframework.jdbc.core.JdbcTemplate", "java.sql.Connection",
         "org.springframework.jdbc.support.rowset.SqlRowSet"],
        ["execute", "executeQuery", "executeUpdate", "batchUpdate", 
         "queryForObject", "queryForMap", "prepareStatement"]
      ) and
      this = ma.getArgument(0) and
      not ma.getArgument(0).isConstant() and
      ma.getArgument(0).toString().matches("(?i)(^SELECT.* | ^INSERT.* | ^UPDATE.*)")
    )
  }
}

class TaintedSqlFlowConfig extends TaintTracking::Configuration {
  TaintedSqlFlowConfig() { this = "TaintedSqlFlowConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof LambdaEventSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof SqlSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
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