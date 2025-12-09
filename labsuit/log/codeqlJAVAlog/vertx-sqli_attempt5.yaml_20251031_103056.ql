/**
 * @name Vertx SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead.
 * @kind problem
 * @id vertx-sqli
 * @security-severity 8.8
 * @security-confidence medium
 * @precision high
 * @tags security
 *       external/cwe/cwe-089
 *       external/cwe/cwe-564
 *       owasp-a01:2017
 *       owasp-a03:2021
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow

class VertxSQLInjectionConfig extends TaintTracking::Configuration {
  VertxSQLInjectionConfig() { this = "VertxSQLInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      source.asExpr() = ma
    )
    or
    exists(AssignExpr assign |
      exists(Expr rhs | rhs = assign.getRValue()) |
      rhs instanceof AddExpr and
      source.asExpr() = assign
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      (
        ma.getMethod().hasName("query") or
        ma.getMethod().hasName("preparedQuery") or
        ma.getMethod().hasName("prepare")
      ) and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlClient") or
        ma.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlConnection")
      ) and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Literal lit |
      lit.getStringValue().matches("^\"...\" \\+ \"...\"$") and
      sanitizer.asExpr() = lit
    )
  }
}

from DataFlow::Node source, DataFlow::Node sink
where
  any(VertxSQLInjectionConfig config).hasFlow(source, sink)
select sink, "Potential SQL injection vulnerability due to un-sanitized input in SQL statement", source,
  "This potentially tainted data flows to a SQL execution point."