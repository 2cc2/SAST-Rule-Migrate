/**
 * @name Turbine SQL Injection
 * @description Detects formatted strings in SQL statements that could lead to SQL injection.
 * @kind problem
 * @id java/turbine-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/cwe/cwe-564
 *       owasp/a1
 *       owasp/a3
 */
import java
import semmle.code.java.dataflow.FlowSources

class SqlStringFormat extends MethodCall {
  SqlStringFormat() {
    exists(Method m |
      m.hasName("executeQuery") and
      m.getDeclaringType().getQualifiedName().matches("BasePeer|GroupPeer") and
      this.getMethod() = m and
      (
        exists(StringLiteral l | l = this.getArgument(0) and l.getValue().matches("%")) or
        exists(AddExpr a | a = this.getArgument(0)) or
        exists(MethodCall mc | 
          mc = this.getArgument(0) and
          mc.getCallee().hasName("format")
        )
      )
    )
  }
}

from SqlStringFormat s
select s, "Detected a formatted string in a SQL statement. This could lead to SQL " +
  "injection if variables in the SQL statement are not properly sanitized. " +
  "Use prepared statements (java.sql.PreparedStatement) instead."