/**
 * @name Spring SQL Injection
 * @description Detected a string argument from a public method contract in a raw SQL statement. 
 *              This could lead to SQL injection if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision high
 * @id java/spring-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.spring.SpringControllers

class SpringSqlInjectionConfig extends TaintTracking::Configuration {
  SpringSqlInjectionConfig() { this = "SpringSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m, Parameter p |
      p = m.getParameter(_) and
      p.getType().hasName("String") and
      m.isPublic() and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma, Method m |
      (m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "PreparedStatementCreatorFactory") and
       m.hasName("<init>") and
       ma.getArgument(0) = sink.asExpr() and
       ma.getMethod() = m)
      or
      (m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
       sink.asExpr() = ma.getArgument(0) and
       ma.getMethod() = m)
      or
      (m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
       m.hasName("batchUpdate") and
       ma.getMethod() = m and
       sink.asExpr() = ma.getAnArgument())
      or
      (m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core.namedparam", "NamedParameterBatchUpdateUtils") and
       sink.asExpr() = ma.getArgument(0) and
       ma.getMethod() = m)
      or
      (m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "BatchUpdateUtils") and
       sink.asExpr() = ma.getArgument(0) and
       ma.getMethod() = m)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(ConstructorCall cc | cc = sanitizer.asExpr())
  }
}

from SpringSqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Potential SQL injection vulnerability from user input to SQL statement in Spring.", 
  source, "User input flows here."