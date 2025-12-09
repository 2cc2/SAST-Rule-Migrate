/**
 * @name JDBC SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
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
import DataFlow::PathGraph

class StringFormatSource extends DataFlow::Node {
  StringFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }
}

class StringConcatSource extends DataFlow::Node {
  StringConcatSource() {
    exists(AssignExpr ae |
      ae.getRight().getType().hasName("String") and
      ae.getLeft().getType().hasName("String") and
      this.asExpr() = ae.getRight()
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      (
        ma.getMethod().hasName("executeQuery") or
        ma.getMethod().hasName("execute") or
        ma.getMethod().hasName("executeUpdate") or
        ma.getMethod().hasName("executeLargeUpdate") or
        ma.getMethod().hasName("addBatch") or
        ma.getMethod().hasName("nativeSQL")
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(Literal lit |
      lit.getType().hasName("String") and
      lit.getStringValue() = "" and
      this.asExpr() = lit
    )
  }
}

class SafeConcatSanitizer extends DataFlow::Node {
  SafeConcatSanitizer() {
    exists(AssignExpr ae |
      ae.getRight().getType().hasName("String") and
      this.asExpr() = ae.getRight()
    )
  }
}

class JdbcSqlInjectionConfig extends TaintTracking::Configuration {
  JdbcSqlInjectionConfig() { this = "JdbcSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or
    source instanceof StringConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof StringLiteralSanitizer or
    sanitizer instanceof SafeConcatSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma |
      ma.getMethod().getParameterType(0).hasName("String") and
      node1.asExpr() = ma.getArgument(0) and
      node2.asExpr() = ma
    ) or
    exists(AssignExpr ae |
      ae.getRight().getType().hasName("String") and
      node1.asExpr() = ae.getRight() and
      node2.asExpr() = ae.getLeft()
    )
  }
}

from JdbcSqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection."