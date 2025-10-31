/**
 * @name Formatted SQL string
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection
 * @kind problem
 * @id java/formatted-sql-string
 * @severity error
 * @tags security
 *   external/cwe/cwe-089
 *   external/owasp/a01
 *   external/owasp/a03
 */

import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() { 
    // Source 1: User input parameters
    exists(ParameterNode p | 
      p.hasName(regexpMatch(".*INPUT.*")) and 
      this.asParameter() = p
    )
    or
    // Source 2: String concatenation methods
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "concat" and 
       ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
      or
      (ma.getMethod().getName() = "append" and
       (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer")))
      or
      (ma.getMethod().getName() = "format" and 
       ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
      or
      (ma.getMethod().getName() = "join" and 
       ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
      and
      this.asExpr() = ma
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      (ma.getMethod().getName() = "execute" or
       ma.getMethod().getName() = "executeQuery" or
       ma.getMethod().getName() = "createQuery" or
       ma.getMethod().getName() = "query" or
       ma.getMethod().getName() = "addBatch" or
       ma.getMethod().getName() = "nativeSQL" or
       ma.getMethod().getName() = "create" or
       ma.getMethod().getName() = "prepare") and
      this.asExpr() = ma.getArgument(0) and
      not regexpMatch(this.getNode().getParent().toString(), ".*TABLE *$") and
      not regexpMatch(this.getNode().getParent().toString(), ".*TABLE %s$")
    )
  }
}

class CriteriaBuilderSanitizer extends DataFlow::Node {
  CriteriaBuilderSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence.criteria", "CriteriaBuilder") and
      this.asExpr() = ma
    )
  }
}

class SqlStringFormatConfig extends TaintTracking::Configuration {
  SqlStringFormatConfig() { this = "SqlStringFormatConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof SqlFormatSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlExecutionSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof CriteriaBuilderSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Propagation for StringBuffer/StringBuilder
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer") or
       ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder")) and
      ma.getMethod().getName() = "append" and
      pred.asExpr() = ma.getArgument(0) and
      succ.asExpr() = ma
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where any(SqlStringFormatConfig cfg).hasFlowPath(source, sink)
select sink.getNode(), "Detected a formatted string in a SQL statement. This could lead to " +
  "SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use prepared statements (java.sql.PreparedStatement) instead."