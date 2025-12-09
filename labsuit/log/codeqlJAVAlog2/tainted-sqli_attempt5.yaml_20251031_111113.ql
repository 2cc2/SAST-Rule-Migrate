/**
 * @name Tainted SQL Injection in AWS Lambda
 * @description Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection.
 * @kind problem
 * @id java/tainted-sqli
 * @severity warning
 * @tags security
 *       sql
 *       aws-lambda
 *       cwe-89
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.aws.Lambda

class LambdaEventSource extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node from, DataFlow::Node to) {
    exists(Method m, Parameter p |
      m.getDeclaringType().getPackage().getName().matches("%aws.lambda%") and
      (
        (m.getSignature().matches("(%$TYPE%,com.amazonaws.services.lambda.runtime.Context)") and
          p.getName() = "$EVENT")
        or
        (m.getSignature().matches("(InputStream%,OutputStream%,com.amazonaws.services.lambda.runtime.Context)") and
          p.getName() = "$EVENT")
      ) and
      from.asParameter() = p and
      to.asExpr() = p.getAnAccess()
    )
  }
}

class SQLSink extends DataFlow::Node {
  SQLSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") or
       ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
       ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "CallableStatement") or
       ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") or
       ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Connection") or
       ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.support.rowset", "SqlRowSet")) and
      (ma.getMethod().hasName(["execute", "executeQuery", "executeUpdate", "batchUpdate",
                             "queryForObject", "queryForMap", "prepareStatement"])) and
      ma.getArgument(0).getStringValue().regexpMatch("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class TaintedSQLFlowConfig extends TaintTracking::Configuration {
  TaintedSQLFlowConfig() { this = "TaintedSQLFlowConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p | 
      (p.getName() = "$EVENT" and
      p.getMethod().getSignature().matches("%com.amazonaws.services.lambda.runtime.Context%")) and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SQLSink }

  override predicate isAdditionalTaintStep(DataFlow::Node from, DataFlow::Node to) {
    from instanceof LambdaEventSource
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedSQLFlowConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), 
  "Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection.",
  source.getNode(), "User input originates from here"