/**
 * @name Formatted SQL string detection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection
 *              if variables in the SQL statement are not properly sanitized. Use a prepared
 *              statements (java.sql.PreparedStatement) instead.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/formatted-sql-string
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class FormattedSqlStringConfig extends TaintTracking::Configuration {
  FormattedSqlStringConfig() { 
    this = "FormattedSqlStringConfig" 
  }

  override predicate isSource(DataFlow::Node source) {
    exists(string concatMethod | 
      concatMethod = ["java.lang.String.concat", "java.lang.StringBuilder.append",
        "java.lang.StringBuffer.append", "java.lang.String.format", "java.lang.String.join"] |
      (
        // Source from method parameters matching input pattern
        exists(Method m, Parameter p | 
          p = m.getAParameter() and
          p.getName().matches("%INPUT%") and
          source.asParameter() = p
        )
        or
        // Source from string concatenation methods
        exists(MethodAccess call |
          call.getCallee().getQualifiedName() = concatMethod and
          source.asExpr() = call
        )
      )
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("execute|executeQuery|createQuery|query|addBatch|nativeSQL|create|prepare") and
      ma.getMethod().getDeclaringType().getQualifiedName() = "java.sql.Statement" and
      ma.getArgument(0) = sink.asExpr() and
      // Exclude certain patterns that are false positives
      not(ma.getArgument(0).toString().matches(".*TABLE *$")) and
      not(ma.getArgument(0).toString().matches(".*TABLE %s$"))
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().getQualifiedName() = "javax.persistence.criteria.CriteriaBuilder" and
      node.asExpr() = ma
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().getQualifiedName() = "java.lang.StringBuilder" or
       ma.getMethod().getDeclaringType().getQualifiedName() = "java.lang.StringBuffer") and
      ma.getMethod().getName() = "append" and
      succ.asExpr() = ma and
      exists(DataFlow::Node arg | arg.asExpr() = ma.getArgument(0) and pred = arg)
    )
  }
}

from FormattedSqlStringConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection " +
       "if variables in the SQL statement are not properly sanitized. Use prepared statements " +
       "(java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using " +
       "'connection.prepareStatement'.", source, "Potential SQL injection source"