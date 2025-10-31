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
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat

class HibernateSqliConfig extends TaintTracking::Configuration {
  HibernateSqliConfig() { this = "HibernateSqliConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or
    exists(AssignmentExpr assign | source.asExpr() = assign |
      assign.getRight().toString().matches("%.*\\+.*") and
      exists(Variable v | assign.getLeft() = v.getAnAccess())
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma | sink.asExpr() = ma |
      ma.getMethod().getName().matches("sqlRestriction|createQuery|createSQLQuery") and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("org.hibernate.criterion", "Restrictions") or
        ma.getMethod().getDeclaringType().hasQualifiedName("org.hibernate", "Session")
      ) and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(AssignmentExpr assign | sanitizer.asExpr() = assign |
      assign.getRight().toString().matches("\".*\" *\\+ *\".*\"")
    )
  }
}

from HibernateSqliConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements instead."