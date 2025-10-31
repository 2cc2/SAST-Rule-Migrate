/**
 * @name Spring SQL Injection
 * @description Detected a string argument from a public method contract in a raw SQL statement.
 * @kind problem
 * @problem.severity warning
 * @id java/spring-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.orm.Jdbc

class PublicStringParameter extends DataFlow::Parameter {
  PublicStringParameter() {
    this.getType() instanceof PrimitiveType and
    this.getType().getName() = "String" and
    this.getParent().isPublic()
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "PreparedStatementCreatorFactory") and
        ma.getMethod().isConstructor()
        or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
        (
          ma.getMethod().hasName("execute") or
          ma.getMethod().hasName("query") or
          ma.getMethod().hasName("update")
        )
        or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
        ma.getMethod().hasName("batchUpdate")
        or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core.namedparam", "NamedParameterBatchUpdateUtils")
        or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core.support", "BatchUpdateUtils")
      ) and
      ma.getEnclosingCallable() = this.asParameter().getParent()
    )
  }
}

class SafeConstructorSanitizer extends DataFlow::Node {
  SafeConstructorSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().isConstructor() and
      this.asExpr() = ma
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

from SpringSQLInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), "Detected a string argument from a public method contract in a raw SQL statement. " +
  "This could lead to SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use prepared statements (java.sql.PreparedStatement) instead."