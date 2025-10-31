/**
 * @name JDBC SQL injection risk from string formatting
 * @description Detects potentially unsafe JDBC queries built with string formatting/concatentation
 * @kind problem
 * @id java/jdbc-sql-formatted-string
 * @severity Warning
 * @tags security
 *       external/cwe/cwe-089
 */
import codeql.java.dataflow.DataFlow
import codeql.java.dataflow.TaintTracking
import codeql.java.Expr
import codeql.java.expr.MethodAccess
import codeql.java.expr.AddExpr

class StringFormatSource extends DataFlow::ExprNode {
  StringFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }
}

class StringConcatSource extends DataFlow::ExprNode {
  StringConcatSource() {
    exists(AddExpr addExpr |
      addExpr.getRightOperand().getStringValue().matches(".*select.*|.*update.*|.*insert.*|.*delete.*") and
      this.asExpr() = addExpr
    )
  }
}

class StringBuilderAppendSource extends DataFlow::ExprNode {
  StringBuilderAppendSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("append") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      ma.getArgument(0).getStringValue().matches(".*select.*|.*update.*|.*insert.*|.*delete.*") and
      this.asExpr() = ma
    )
  }
}

class JdbcQuerySink extends DataFlow::ParameterNode {
  JdbcQuerySink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("queryForObject", "queryForList", "update", "execute", "insert") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      this.asParameter() = ma.getArgument(0)
    )
  }
}

class ParameterizedQuerySanitizer extends DataFlow::ExprNode {
  ParameterizedQuerySanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("queryForObject") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      ma.getArgument(0).getStringValue().matches(".*\\?.*") and
      this.asExpr() = ma
    )
  }
}

class TaintTrackingConfig extends TaintTracking::Configuration {
  TaintTrackingConfig() { this = "TaintTrackingConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or
    source instanceof StringConcatSource or
    source instanceof StringBuilderAppendSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof JdbcQuerySink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof ParameterizedQuerySanitizer
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintTrackingConfig config
where config.hasFlowPath(source, sink)
select sink, "Possible JDBC injection detected. Use parameterized queries instead of string concatenation."