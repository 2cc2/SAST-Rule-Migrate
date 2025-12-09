/**
 * @name JDBC SQL injection risk from string formatting
 * @description Detects potentially unsafe JDBC queries built with string formatting/concatentation
 * @kind problem
 * @id java/jdbc-sql-formatted-string
 * @severity Warning
 * @tags security
 *       external/cwe/cwe-089
 */
import java
import DataFlow
import DataFlow::PathGraph
import Expr
import AddExpr

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
    exists(AddExpr addExpr |
      addExpr.getRightOperand().toString().regexpMatch(".*select.*|.*update.*|.*insert.*|.*delete.*") and
      this.asExpr() = addExpr
    )
  }
}

class StringBuilderAppendSource extends DataFlow::Node {
  StringBuilderAppendSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("append") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      ma.getArgument(0).toString().regexpMatch(".*select.*|.*update.*|.*insert.*|.*delete.*") and
      this.asExpr() = ma
    )
  }
}

class JdbcQuerySink extends DataFlow::Node {
  JdbcQuerySink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("queryForObject", "queryForList", "update", "execute", "insert") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      ma.getArgument(0) = this.asExpr()
    )
  }
}

class ParameterizedQuerySanitizer extends DataFlow::Node {
  ParameterizedQuerySanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("queryForObject") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      ma.getArgument(0).toString().matches("%\\?%") and
      this.asExpr() = ma
    )
  }
}

module TaintTrackingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or
    source instanceof StringConcatSource or
    source instanceof StringBuilderAppendSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof JdbcQuerySink
  }

  predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof ParameterizedQuerySanitizer
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where DataFlow::flowPath(source, sink, new TaintTrackingConfig())
select sink, "Possible JDBC injection detected. Use parameterized queries instead of string concatenation."