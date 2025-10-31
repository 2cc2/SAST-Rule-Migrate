/**
 * @name Spring SQL Injection Vulnerability
 * @description Detects string arguments from public method contracts
 *              used in raw SQL statements without proper sanitation
 * @kind problem
 * @id java/spring-sqli
 * @security-severity 8.0
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Spring.SpringJDBCTemplate
import semmle.code.java.frameworks.JDBCTaintStep
import semmle.code.java.dataflow.DataFlow

class PublicStringParameter extends DataFlow::Node {
  PublicStringParameter() {
    exists(Parameter p |
      p.getType().hasName("String") and
      p.getCallable().isPublic() and
      this.asParameter() = p
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    // PreparedStatementCreatorFactory constructor
    exists(MethodAccess ma |
      ma.getMethod().hasName("<init>") and
      ma.getMethod().getDeclaringType().hasQualifiedName("", "PreparedStatementCreatorFactory") and
      ma.getArgument(0) = this.asExpr()
    )
    or
    // JdbcTemplate any method with SQL argument
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      ma.getArgument(0) = this.asExpr()
    )
    or
    // JdbcTemplate batchUpdate method
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("batchUpdate") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      this.asExpr() = ma.getAnArgument()
    )
    or
    // NamedParameterBatchUpdateUtils any method with SQL argument
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core.namedparam", "NamedParameterBatchUpdateUtils") and
      ma.getArgument(0) = this.asExpr()
    )
    or
    // BatchUpdateUtils any method with SQL argument
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "BatchUpdateUtils") and
      ma.getArgument(0) = this.asExpr()
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

class SpringSqlInjectionConfig extends TaintTracking::Configuration {
  SpringSqlInjectionConfig() { this = "SpringSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof PublicStringParameter
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SafeConstructorSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    any(JDBCTaintStep jdbcStep).propagatesTaint(pred, succ)
  }
}

from SpringSqlInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, 
  "Detected a string argument from a public method contract in a raw SQL statement. " +
  "This could lead to SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use prepared statements (java.sql.PreparedStatement) instead."