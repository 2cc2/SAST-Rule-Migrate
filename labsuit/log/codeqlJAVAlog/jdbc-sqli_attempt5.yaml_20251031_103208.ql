/**
 * @name JDBC SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection 
 *              if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision medium
 * @id java/jdbc-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import semmle.code.java.dataflow.DataFlow

predicate isSource(DataFlow::Node source) {
  exists(MethodAccess ma |
    ma.getMethod().hasQualifiedName("java.lang", "String", "format") and
    source.asExpr() = ma
  )
  or
  exists(AssignmentExpr assign |
    assign.getRight().getType().hasName("String") and
    regexMatches("String \\$SQL = \\$X \\+ \\$Y;", assign.toString()) and
    source.asExpr() = assign
  )
}

predicate isSink(DataFlow::Node sink) {
  exists(MethodAccess ma |
    ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
    regexMatches("^(executeQuery|execute|executeUpdate|executeLargeUpdate|addBatch|nativeSQL)$", 
                ma.getMethod().getName()) and
    sink.asExpr() = ma.getArgument(0)
  )
  or
  exists(MethodAccess ma |
    ma.getMethod().hasQualifiedName("java.lang", "String", "format") and
    exists(MethodAccess parent |
      parent = ma.getEnclosingCallable() and
      regexMatches("\\$S\\.\\$METHOD\\(String.format\\(.*\\),.*\\)", parent.toString())
    ) and
    sink.asExpr() = ma
  )
}

predicate isSanitizer(DataFlow::Node sanitizer) {
  exists(StringLiteral lit |
    regexMatches("^\"\" \\+ \"\"$", lit.toString()) and
    sanitizer.asExpr() = lit
  )
  or
  exists(AssignmentExpr assign |
    assign.getVariable().getType().hasName("String") and
    regexMatches("String \\$SQL = \".*\" \\+ \".*\";", assign.toString()) and
    sanitizer.asExpr() = assign
  )
}

predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(MethodAccess ma, Parameter p |
    ma.getMethod().getName() matches "\\$FUNC" and
    ma.getArgument(0) = node1.asExpr() and
    p = ma.getArgument(0) and
    regexMatches("\\$VAL \\$FUNC\\(.*String \\$SQL.*\\)", ma.toString()) and
    node2.asParameter() = p
  )
  or
  exists(AssignmentExpr assign |
    assign.getRight() = node1.asExpr() and
    assign.getVariable() = node2.asExpr()
  )
}

class JdbcSqlInjectionConfig extends TaintTracking::Configuration {
  JdbcSqlInjectionConfig() { this = "JdbcSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    isSource(source)
  }

  override predicate isSink(DataFlow::Node sink) {
    isSink(sink)
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    isSanitizer(sanitizer)
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    isAdditionalTaintStep(node1, node2)
  }
}

from JdbcSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if " +
  "variables in the SQL statement are not properly sanitized. Use prepared statements " +
  "(java.sql.PreparedStatement) instead.", source.getNode(), "Potential SQL injection"