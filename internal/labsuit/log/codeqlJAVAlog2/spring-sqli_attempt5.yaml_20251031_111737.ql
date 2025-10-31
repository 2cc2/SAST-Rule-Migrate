/**
 * @name Spring SQL Injection
 * @description Detected a string argument from a public method contract in a raw SQL statement.
 * @kind problem
 * @id java/spring-sqli
 * @security-severity 8.8
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */
import java
import semmle.code.java.Method
import semmle.code.java.Parameter
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.Call
import semmle.code.java.Constructor

class SpringSqlInjectionConfig extends TaintTracking::Configuration {
  SpringSqlInjectionConfig() { this = "SpringSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m, Parameter p |
      m.isPublic() and
      m.getAParameter() = p and
      p.getType().hasName("String") and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call c, Method m |
      (m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") or
       m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "NamedParameterBatchUpdateUtils") or
       m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "BatchUpdateUtils") or
       (m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "PreparedStatementCreatorFactory") and
        m instanceof Constructor)) and
      c.getCallee() = m and
      sink.asExpr() = c.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Call c |
      c instanceof Constructor and
      sanitizer.asExpr() = c
    )
  }
}

from SpringSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), "Detected a string argument from a public method contract in a raw SQL statement. " +
  "This could lead to SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use prepared statements (java.sql.PreparedStatement) instead. " +
  "You can obtain a PreparedStatement using 'connection.prepareStatement'."