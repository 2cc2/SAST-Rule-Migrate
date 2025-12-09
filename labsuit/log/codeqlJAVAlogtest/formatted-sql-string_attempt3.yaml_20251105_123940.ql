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
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat

class FormattedSqlStringConfig extends TaintTracking::Configuration {
  FormattedSqlStringConfig() { this = "FormattedSqlStringConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodParameter p | 
      source.asParameter() = p and
      p.getType() instanceof TypeString and
      p.getName().matches("%INPUT%")
    )
    or
    exists(MethodAccess ma |
      source.asExpr() = ma and
      (ma.getMethod().getName() = "concat" and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
      or
      (ma.getMethod().getName() = "append" and 
        (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
         ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer")))
      or
      (ma.getMethod().getName() = "format" and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
      or
      (ma.getMethod().getName() = "join" and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      sink.asExpr() = ma and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      ma.getMethod().getName().matches("execute|executeQuery|createQuery|query|addBatch|nativeSQL|create|prepare") and
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

from FormattedSqlStringConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source.getNode(), 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'."