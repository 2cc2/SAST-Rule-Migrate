/**
 * @name Spring SQL Injection
 * @description Detected a string argument from a public method contract in a raw SQL statement.
 * @id spring-sqli
 * @kind problem
 * @severity warning
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.JDBCTaintStep

class PublicStringParameter extends FlowSources::ParameterNode {
  PublicStringParameter() {
    exists(Method m | m = this.getParameter().getCallable() |
      m.isPublic() and
      this.getParameter().getType() instanceof TypeString
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      ma = this.asExpr() |
      (
        ma.getMethod().getName() = "constructor" and
        ma.getMethod().getDeclaringType().hasName("PreparedStatementCreatorFactory")
      ) or
      (
        ma.getMethod().getDeclaringType().hasName("JdbcTemplate")
      ) or
      (
        ma.getMethod().getName() = "batchUpdate" and
        ma.getMethod().getDeclaringType().hasName("JdbcTemplate")
      ) or
      (
        ma.getMethod().getDeclaringType().hasName("NamedParameterBatchUpdateUtils")
      ) or
      (
        ma.getMethod().getDeclaringType().hasName("BatchUpdateUtils")
      )
    )
  }
}

class SafeConstructorSanitizer extends DataFlow::Node {
  SafeConstructorSanitizer() {
    exists(MethodAccess ma |
      ma = this.asExpr() |
      ma.getMethod().getName() = "constructor"
    )
  }
}

class SpringSQLInjectionConfig extends TaintTracking::Configuration {
  SpringSQLInjectionConfig() { this = "SpringSQLInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof PublicStringParameter
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SafeConstructorSanitizer
  }
}

from SpringSQLInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Detected a string argument from a public method contract in a raw SQL statement. " +
  "This could lead to SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use a prepared statements (java.sql.PreparedStatement) instead."