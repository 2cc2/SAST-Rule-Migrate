/**
 * @name Formatted SQL String
 * @description Detected a formatted string in a SQL statement. This could lead to SQL
 * injection if variables in the SQL statement are not properly sanitized.
 * Use a prepared statements (java.sql.PreparedStatement) instead.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/formatted-sql-string
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma, Method m | 
      ma.getMethod() = m and
      m.hasName("getParameter") and
      m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      source.asExpr() = ma
    )
    or
    exists(Parameter p | 
      p.getType().hasName("String") and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma, Method m | 
      ma.getMethod() = m and
      m.getName().matches("execute%") or
      m.getName().matches("create%") or
      m.getName().matches("prepare%") or
      m.getName().matches("query%") or
      m.getName().matches("nativeSQL") or
      m.getName().matches("addBatch") and
      m.getDeclaringType().hasQualifiedName("java.sql", "Statement") or
      m.getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
      m.getDeclaringType().hasQualifiedName("java.sql", "Connection") or
      m.getDeclaringType().hasQualifiedName("javax.persistence", "EntityManager") and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence.criteria", "CriteriaBuilder") and
      sanitizer.asExpr() = ma
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "append" and
      (ma.getMethod().getDeclaringType().hasName("StringBuilder") or
       ma.getMethod().getDeclaringType().hasName("StringBuffer")) and
      node1.asExpr() = ma.getArgument(0) and
      node2.asExpr() = ma.getQualifier()
    )
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SQL injection. User input flows into SQL statement."