/**
 * @name Vert.x SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables 
 * in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead.
 * @kind problem
 * @id java/vertx-sqli
 * @severity warning
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */
import java
import DataFlow
import TaintTracking

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "format" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this = ma
    )
  }
}

class SqlConcatSource extends DataFlow::Node {
  SqlConcatSource() {
    exists(Assignment assign |
      assign.getRight().getType().hasName("String") and
      this = assign.getRight() and
      assign.toString().matches("String \\$SQL = \\$X \\+ \\$Y")
    )
  }
}

class SqlExecuteSink extends DataFlow::Node {
  SqlExecuteSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getName().regexpMatch("query|preparedQuery|prepare")) and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlClient") or
        ma.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlConnection")
      ) and
      this = ma.getArgument(0)
    )
  }
}

class SqlLiteralSanitizer extends DataFlow::Node {
  SqlLiteralSanitizer() {
    exists(Literal lit |
      this = lit and
      lit.toString().regexpMatch("\\\"...\\\" \\+ \\\"...\\\"")
    )
  }
}

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlFormatSource or source instanceof SqlConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecuteSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SqlLiteralSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Parameter p |
      node1 = p and
      node2 = p.getAnAccess()
    )
  }
}

from SqlInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection if " +
  "variables in the SQL statement are not properly sanitized. Use prepared statements " +
  "(java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'."