/**
 * @name SQL Injection in Spring Framework
 * @description Detected a string argument from a public method contract in a raw SQL statement.
 *              This could lead to SQL injection if variables in the SQL statement are not properly
 *              sanitized. Use prepared statements (java.sql.PreparedStatement) instead.
 * @kind problem
 * @problem.severity warning
 * @id java/spring-sqli
 * @precision high
 * @tags security
 *       cwe: "CWE-89"
 *       owasp: "A01:2017"
 *       owasp: "A03:2021"
 */

import java
import semmle.code.java.frameworks.spring.Spring
import semmle.code.java.dataflow.DataFlow

class PublicStringParameter extends DataFlow::Node {
  PublicStringParameter() {
    exists(Method m, Parameter p |
      this.asParameter() = p and
      p.getType() instanceof TypeString and
      m = p.getMethod() and
      m.isPublic() and
      this = p.asSource()
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    // PreparedStatementCreatorFactory constructor
    exists(Call c |
      c = this.asExpr() and
      c.getCallee().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "PreparedStatementCreatorFactory") and
      c.getCallee().isConstructor() and
      this.asExpr() = c.getArgument(0)
    ) or
    // JdbcTemplate methods
    exists(Call c |
      c = this.asExpr() and
      c.getCallee().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      this.asExpr() = c.getArgument(0)
    ) or
    // JdbcTemplate.batchUpdate
    exists(Call c |
      c = this.asExpr() and
      c.getCallee().getName() = "batchUpdate" and
      c.getCallee().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate")
    ) or
    // NamedParameterBatchUpdateUtils methods
    exists(Call c |
      c = this.asExpr() and
      c.getCallee().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core.namedparam", "NamedParameterBatchUpdateUtils") and
      this.asExpr() = c.getArgument(0)
    ) or
    // BatchUpdateUtils methods
    exists(Call c |
      c = this.asExpr() and
      c.getCallee().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "BatchUpdateUtils") and
      this.asExpr() = c.getArgument(0)
    )
  }
}

class SafeConstructorSanitizer extends DataFlow::BarrierGuard {
  SafeConstructorSanitizer() {
    exists(Call c |
      c = this.asExpr() and
      c.getCallee().isConstructor()
    )
  }
}

module TaintFlow = TaintTracking::Global<PublicStringParameter, SqlExecutionSink, SafeConstructorSanitizer>;

from TaintFlow::PathNode source, TaintFlow::PathNode sink
where TaintFlow::flow(source, sink)
select sink.getNode(), source.getNode() + " flows to SQL execution sink here. " +
  "This could lead to SQL injection if variables are not properly sanitized. " +
  "Use prepared statements (java.sql.PreparedStatement) instead."