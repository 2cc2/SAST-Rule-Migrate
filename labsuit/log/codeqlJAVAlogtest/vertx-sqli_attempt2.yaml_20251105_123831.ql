/**
 * @id vertx-sqli
 * @severity WARNING
 * @message Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @security-severity 8.8
 * @cwe "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
 * @owasp ["A01:2017 - Injection", "A03:2021 - Injection"]
 * @tags security
 * @language java
 */

import java
import semmle.code.java.dataflow.TaintTracking

class FormattedSqlSource extends DataFlow::Node {
  FormattedSqlSource() {
    exists(MethodCall ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }
}

class ConcatSqlSource extends DataFlow::Node {
  ConcatSqlSource() {
    exists(AssignExpr assign |
      assign.getRValue().toString().matches("String \\$SQL = \\$X \\+ \\$Y") and
      this.asExpr() = assign.getRValue()
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(MethodCall ma |
      (
        ma.getMethod().hasName(["query", "preparedQuery", "prepare"]) and
        (
          ma.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlClient") or
          ma.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlConnection")
        )
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class SqlSanitizer extends DataFlow::Node {
  SqlSanitizer() {
    exists(Literal lit |
      lit.getStringValue().matches("^\\\"...\\\" \\+ \\\"...\\\"$") and
      this.asExpr() = lit
    )
  }
}

class VertxSqlInjectionConfig extends TaintTracking::Configuration {
  VertxSqlInjectionConfig() { this = "VertxSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof FormattedSqlSource or
    source instanceof ConcatSqlSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SqlSanitizer
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, VertxSqlInjectionConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection."