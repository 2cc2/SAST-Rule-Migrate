import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

/**
 * @id formatted-sql-string
 * @severity ERROR
 * @message Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.
 * @metadata {
 *   "language": "java",
 *   "category": "security",
 *   "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
 *   "owasp": ["A01:2017 - Injection", "A03:2021 - Injection"],
 *   "references": [
 *     "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
 *     "https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html#create_ps",
 *     "https://software-security.sans.org/developer-how-to/fix-sql-injection-in-java-using-prepared-callable-statement"
 *   ]
 * }
 */
class FormattedSqlStringConfig extends TaintTracking::Configuration {
  FormattedSqlStringConfig() { this = "Formatted Sql String" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodParameter p |
      source.asParameter() = p and
      matches(p.getName(), ".*INPUT")
    )
    or
    exists(MethodAccess ma |
      source.asExpr() = ma and
      (
        ma.getMethod().getName() = "concat" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")
        or
        ma.getMethod().getName() = "append" and
        (
          ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
          ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer")
        )
        or
        ma.getMethod().getName() = "format" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")
        or
        ma.getMethod().getName() = "join" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")
      )
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      sink.asExpr() = ma.getArgument(0) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      (
        ma.getMethod().getName().matches("execute%") or
        ma.getMethod().getName() = "createQuery" or
        ma.getMethod().getName() = "query" or
        ma.getMethod().getName() = "addBatch" or
        ma.getMethod().getName() = "nativeSQL" or
        ma.getMethod().getName() = "create" or
        ma.getMethod().getName() = "prepare"
      ) and
      not ma.getArgument(0).toString().matches(".*TABLE *$") and
      not ma.getArgument(0).toString().matches(".*TABLE %s$")
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodAccess ma |
      sanitizer.asExpr() = ma and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence.criteria", "CriteriaBuilder")
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma |
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer") and
        ma.getMethod().getName() = "append"
        or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
        ma.getMethod().getName() = "append"
      ) and
      node1.asExpr() = ma.getArgument(0) and
      node2.asExpr() = ma
    )
  }
}

from FormattedSqlStringConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection."