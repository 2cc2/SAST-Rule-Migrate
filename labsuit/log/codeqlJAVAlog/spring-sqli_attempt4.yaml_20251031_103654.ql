/**
 * @name Spring SQL Injection
 * @description Detected a string argument from a public method contract in a raw SQL statement.
 * @kind problem
 * @id java/spring-sqli
 * @problem.severity warning
 * @security-severity 8.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.JDBCTaintStep

class PublicStringParameter extends Parameter {
  PublicStringParameter() {
    exists(Method m | this.getAnnotatedType().getUnderlyingType().hasName("String") and
      m = this.getMethod() and m.isPublic()
    )
  }
}

class SqlExecutionSink extends MethodAccess {
  SqlExecutionSink() {
    (
      this.getMethod().getDeclaringType().getName().matches("PreparedStatementCreatorFactory") and
      this.getMethod().isConstructor()
    ) or
    (
      this.getMethod().getDeclaringType().getName().matches("JdbcTemplate") and
      this.getArgument(0).getType().hasName("String")
    ) or
    (
      this.getMethod().getDeclaringType().getName().matches("NamedParameterBatchUpdateUtils") and
      this.getArgument(0).getType().hasName("String")
    ) or
    (
      this.getMethod().getDeclaringType().getName().matches("BatchUpdateUtils") and
      this.getArgument(0).getType().hasName("String")
    )
  }
}

class SafeConstructorSanitizer extends MethodAccess {
  SafeConstructorSanitizer() {
    this.getMethod().isConstructor()
  }
}

class SpringSqlTaintConfig extends TaintTracking::Configuration {
  SpringSqlTaintConfig() { this = "SpringSqlTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asParameter() instanceof PublicStringParameter
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SqlExecutionSink sqlSink | sqlSink = sink.asExpr())
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(SafeConstructorSanitizer sanitizer | sanitizer = node.asExpr())
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    JDBCTaintStep::jdbcTaintStep(node1, node2)
  }
}

from SpringSqlTaintConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Detected a string argument from a public method contract in a raw SQL statement. " +
  "This could lead to SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use prepared statements (java.sql.PreparedStatement) instead."