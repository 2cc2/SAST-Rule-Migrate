/**
 * @name Hibernate SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id java/hibernate-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

private class StringFormatSource extends DataFlow::Node {
  StringFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }
}

private class StringConcatSource extends DataFlow::Node {
  StringConcatSource() {
    exists(AssignmentExpr assign |
      assign.getRight().getType().hasName("String") and
      assign.getRight().toString().matches("%String.*=.*\\+.*%") and
      this.asExpr() = assign
    )
  }
}

private class HibernateSqlRestrictionSink extends DataFlow::Node {
  HibernateSqlRestrictionSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("sqlRestriction") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.hibernate.criterion", "Restrictions") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

private class HibernateSessionSink extends DataFlow::Node {
  HibernateSessionSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getName().matches("createQuery") or
       ma.getMethod().getName().matches("createSQLQuery")) and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.hibernate", "Session") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

private class StringLiteralSanitizer extends DataFlow::BarrierGuard {
  StringLiteralSanitizer() {
    exists(AssignmentExpr assign |
      assign.getRight().getType().hasName("String") and
      assign.getRight().toString().matches("%String.*=.*\".*\" *\\+ *\".*\"%") and
      this.asExpr() = assign
    )
  }
}

class HibernateSQLIConfig extends TaintTracking::Configuration {
  HibernateSQLIConfig() { this = "HibernateSQLIConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or
    source instanceof StringConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof HibernateSqlRestrictionSink or
    sink instanceof HibernateSessionSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof StringLiteralSanitizer
  }
}

from HibernateSQLIConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables are not properly sanitized. Use prepared statements instead."