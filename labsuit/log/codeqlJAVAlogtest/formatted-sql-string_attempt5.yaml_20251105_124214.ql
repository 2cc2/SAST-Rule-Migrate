/**
 * @name Formatted SQL string
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection
 *              if variables in the SQL statement are not properly sanitized.
 * @kind problem
 * @id java/formatted-sql-string
 * @severity error
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Struts

class FormattedSqlStringConfig extends TaintTracking::Configuration {
  FormattedSqlStringConfig() { this = "FormattedSqlStringConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p | 
      source.asParameter() = p and
      p.getType() instanceof TypeString and
      p.getName().matches(".*INPUT.*")
    )
    or
    exists(MethodAccess ma |
      source.asExpr() = ma and
      (ma.getMethod().hasName("concat") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
      or
      (ma.getMethod().hasName("append") and 
        (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
         ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer")))
      or
      (ma.getMethod().hasName("format") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
      or
      (ma.getMethod().hasName("join") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      sink.asExpr() = ma and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      ma.getMethod().getName().matches("execute%") or
      ma.getMethod().getName().matches("executeQuery%") or
      ma.getMethod().getName().matches("createQuery%") or
      ma.getMethod().getName().matches("query%") or
      ma.getMethod().getName().matches("addBatch%") or
      ma.getMethod().getName().matches("nativeSQL%") or
      ma.getMethod().getName().matches("create%") or
      ma.getMethod().getName().matches("prepare%") and
      ma.getArgument(0) = sink.asExpr() and
      not ma.getArgument(0).toString().matches(".*TABLE *$") and
      not ma.getArgument(0).toString().matches(".*TABLE %s$")
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(MethodAccess ma |
      node.asExpr() = ma and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence.criteria", "CriteriaBuilder")
    )
  }
}

from FormattedSqlStringConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'."