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
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "format" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }
}

class SqlConcatSource extends DataFlow::Node {
  SqlConcatSource() {
    exists(Assignment assign |
      assign.getRight().getType().hasName("String") and
      this.asExpr() = assign.getRight() and
      regexpMatches(assign.toString(), "String \\$SQL = \\$X \\+ \\$Y")
    )
  }
}

class SqlExecuteSink extends DataFlow::Node {
  SqlExecuteSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getName() matches "query|preparedQuery|prepare" and
        (
          ma.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlClient") or
          ma.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlConnection")
        ) and
        this.asExpr() = ma.getArgument(0)
      )
    )
  }
}

class SqlLiteralSanitizer extends DataFlow::Node {
  SqlLiteralSanitizer() {
    exists(Literal lit |
      this.asExpr() = lit and
      regexpMatches(lit.toString(), "^\"...\" \\+ \"...\"$")
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
    exists(MethodAccess ma |
      ma.getMethod() instanceof Parameter and
      node1.asParameter() = ma.getMethod() and
      node2.asExpr() = ma.getArgument(0)
    )
  }
}

from SqlInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection if " +
  "variables in the SQL statement are not properly sanitized. Use prepared statements " +
  "(java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'."