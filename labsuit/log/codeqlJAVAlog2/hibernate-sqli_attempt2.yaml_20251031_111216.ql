/**
 * @name Hibernate SQL Injection
 * @description Detected a formatted string in a SQL statement. Vulnerable to SQL injection.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision high
 * @id java/hibernate-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 *       java
 *       hibernate
 */

import java
import DataFlow::PathGraph
import DataFlow::TaintTracking
import semmle.code.java.StringFormatter

class HibernateSqliConfig extends TaintTracking::Configuration {
  HibernateSqliConfig() { this = "HibernateSqliConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(FormatMethod format | source.asExpr() = format.getACall()) or
    exists(AssignExpr assign | source.asExpr() = assign |
      assign.getRValue().getText().matches("%.*\\+.*") and
      exists(VariableAccess va | assign.getLValue() = va)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc | sink.asExpr() = mc |
      mc.getMethod().getName().matches("sqlRestriction|createQuery|createSQLQuery") and
      (
        mc.getMethod().getDeclaringType().hasQualifiedName("org.hibernate.criterion", "Restrictions") or
        mc.getMethod().getDeclaringType().hasQualifiedName("org.hibernate", "Session")
      ) and
      sink.asExpr() = mc.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(AssignExpr assign | sanitizer.asExpr() = assign |
      assign.getRValue().getText().matches("\".*\" *\\+ *\".*\"")
    )
  }
}

from HibernateSqliConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements instead."