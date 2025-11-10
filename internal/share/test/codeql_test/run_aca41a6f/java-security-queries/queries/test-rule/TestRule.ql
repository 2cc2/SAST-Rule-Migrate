/**
 * @name Spring SQL Injection
 * @description Detected a string argument from a public method contract in a raw SQL statement.
 *              This could lead to SQL injection if variables in the SQL statement are not
 *              properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead.
 * @kind path-problem
 * @problem.severity warning
 * @id java/spring-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/cwe/cwe-2021-top25
 *       external/cwe/cwe-2022-top25
 *       owasp-a01
 *       owasp-a03
 */

import java
import semmle.code.java.dataflow.TaintTracking

class SpringSqlInjectionConfig extends TaintTracking::Configuration {
  SpringSqlInjectionConfig() { this = "SpringSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m, Parameter p |
      m.isPublic() and
      p.getType().hasName("String") and
      p = source.asParameter() and
      p.getCallable() = m
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(ConstructorCall cc |
      sanitizer.asExpr() = cc.getAnArgument()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // PreparedStatementCreatorFactory sink
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("org.springframework.jdbc.core", "PreparedStatementCreatorFactory") and
      sink.asExpr() = cc.getAnArgument()
    )
    or
    // JdbcTemplate sink
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      sink.asExpr() = ma.getAnArgument()
    )
    or
    // JdbcTemplate.batchUpdate sink
    exists(MethodAccess ma |
      ma.getMethod().getName() = "batchUpdate" and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      exists(Parameter p |
        p.getType().hasName("String") and
        sink.asParameter() = p
      )
    )
    or
    // NamedParameterBatchUpdateUtils sink
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core.namedparam", "NamedParameterBatchUpdateUtils") and
      sink.asExpr() = ma.getAnArgument()
    )
    or
    // BatchUpdateUtils sink
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "BatchUpdateUtils") and
      sink.asExpr() = ma.getAnArgument()
    )
  }
}

from SpringSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SQL injection vulnerability from $@.",
  source.getNode(), "user input"