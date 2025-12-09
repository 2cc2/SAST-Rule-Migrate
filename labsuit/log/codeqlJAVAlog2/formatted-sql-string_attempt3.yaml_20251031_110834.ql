/**
 * @name Formatted SQL string
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection
 *              if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity error
 * @id java/formatted-sql-string
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import DataFlow::PathGraph
import semmle.code.java.dataflow.TaintTracking

class SQLInjectionConfig extends TaintTracking::Configuration {
  SQLInjectionConfig() { this = "SQLInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asParameter().getType().hasName("String") and
    (
      source.asParameter().getName().matches("%INPUT%") or
      exists(Method m | 
        m.getName().matches("getParameter") and
        m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest") and
        source.asParameter() = m.getAParameter()
      )
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      ma.getMethod().getName().matches("execute%") and
      sink.asExpr() = ma.getArgument(0)
    ) and
    not sink.asExpr().getParent().toString().matches(".*TABLE\\s*\\$") and
    not sink.asExpr().getParent().toString().matches(".*TABLE\\s*%s\\$")
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence.criteria", "CriteriaBuilder") and
      sanitizer.asExpr() = ma
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer")
      ) and
      ma.getMethod().getName().matches("append") and
      pred.asExpr() = ma.getArgument(0) and
      succ.asExpr() = ma
    )
  }
}

from SQLInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables " +
  "in the SQL statement are not properly sanitized. Use prepared statements instead."