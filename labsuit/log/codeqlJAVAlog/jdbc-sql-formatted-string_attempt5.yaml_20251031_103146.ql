/**
 * @name Possible JDBC injection
 * @description Detects potential JDBC injection vulnerabilities when using string concatenation or formatting
 *              instead of parameterized queries
 * @kind path-problem
 * @problem.severity warning
 * @id java/jdbc-sql-formatted-string
 * @tags security
 *       external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class SqlStringFormatSource extends DataFlow::Expr {
  SqlStringFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("java.lang.String", "format") and
      this = ma.getArgument(0).getExpr()
    )
  }
}

class SqlStringConcatSource extends DataFlow::Expr {
  SqlStringConcatSource() {
    exists(BinaryExpr be |
      be.getOperator() = OP_PLUS and
      be.getLeftOperand().getLiteralValue().regexpMatch(".*select.*|.*update.*|.*insert.*|.*delete.*") and
      this = be.getRightOperand().getExpr()
    )
  }
}

class SqlStringBuilderAppendSource extends DataFlow::Expr {
  SqlStringBuilderAppendSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("java.lang.StringBuilder", "append") and
      ma.getArgument(0).getLiteralValue().regexpMatch(".*select.*|.*update.*|.*insert.*|.*delete.*") and
      this = ma.getQualifier().getExpr()
    )
  }
}

class JdbcSink extends DataFlow::Node {
  JdbcSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", "queryForObject") or
        ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", "queryForList") or
        ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", "update") or
        ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", "execute") or
        ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", "insert")
      ) and
      this.asParameter() = ma.getArgument(0)
    )
  }
}

class ParameterizedQuerySanitizer extends TaintTracking::Sanitizer {
  ParameterizedQuerySanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", "queryForObject") and
      ma.getArgument(0).getLiteralValue().regexpMatch(".*\\?.*")
    )
  }
}

class JdbcTaintConfig extends TaintTracking::Configuration {
  JdbcTaintConfig() { this = "JdbcTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlStringFormatSource or
    source instanceof SqlStringConcatSource or
    source instanceof SqlStringBuilderAppendSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof JdbcSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof ParameterizedQuerySanitizer
  }
}

from JdbcTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), "Possible JDBC injection detected. Use the parameterized query feature " +
  "available in queryForObject instead of concatenating or formatting strings: " +
  "<code>jdbc.queryForObject(\"select * from table where name = ?\", Integer.class, parameterName);</code>",
  source.getNode(), "User input flows into SQL query here"