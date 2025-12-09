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
import codeql.java.security.QueryInjection
import codeql.java.dataflow.DataFlow
import codeql.java.dataflow.TaintTracking
import codeql.java.Method
import codeql.java.Parameter
import codeql.java.MethodAccess

class SQLInjectionConfig extends TaintTracking::Configuration {
  SQLInjectionConfig() { this = "SQLInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      p = source.asParameter() and
      p.getType().hasName("String") and
      (
        p.getName().matches("%INPUT%") or
        exists(Method m | 
          m.getName().matches("getParameter") and
          m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest") and
          p = m.getAParameter()
        )
      )
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      ma.getMethod().getName().matches("execute%|query|createQuery|addBatch|nativeSQL|create|prepare") and
      sink.asExpr() = ma.getArgument(0) and
      not ma.getArgument(0).toString().matches("%TABLE\\s*\\$") and
      not ma.getArgument(0).toString().matches("%TABLE\\s*%s\\$")
    )
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
      ma.getMethod().getName() = "append" and
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