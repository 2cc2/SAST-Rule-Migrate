/**
 * @name jdbc-sql-formatted-string
 * @description Possible JDBC injection detected. Use the parameterized query feature available in queryForObject instead of concatenating or formatting strings
 * @kind path-problem
 * @problem.severity Warning
 * @id java/jdbc-sql-formatted-string
 * @tags security
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat

class TaintedSqlSource extends DataFlow::Node {
  TaintedSqlSource() {
    exists(MethodAccess ma |
      (ma.getMethod().hasName("format") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")) or
      (ma.getMethod().hasName("append") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
       ma.getArgument(0).toString().regexpMatch(".*select.*|.*update.*|.*insert.*|.*delete.*"))
    ) and
    this.asExpr() = ma
  )
}

class StringConcatSource extends DataFlow::Node {
  StringConcatSource() {
    exists(BinaryExpr be |
      be.getOperator() = "+" and
      be.getLeftOperand().toString().regexpMatch(".*select.*|.*update.*|.*insert.*|.*delete.*") and
      this.asExpr() = be
    )
  }
}

class JdbcSink extends DataFlow::Node {
  JdbcSink() {
    exists(MethodAccess ma |
      (ma.getMethod().hasName("queryForObject") or
       ma.getMethod().hasName("queryForList") or
       ma.getMethod().hasName("update") or
       ma.getMethod().hasName("execute") or
       ma.getMethod().hasName("insert")) and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class ParameterizedQuerySanitizer extends DataFlow::Node {
  ParameterizedQuerySanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("queryForObject") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      ma.getArgument(0).toString().regexpMatch(".*\\?.*") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class JdbcTaintConfig extends TaintTracking::Configuration {
  JdbcTaintConfig() { this = "JdbcTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof TaintedSqlSource or source instanceof StringConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof JdbcSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof ParameterizedQuerySanitizer
  }
}

from JdbcTaintConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Possible JDBC injection detected. Use the parameterized query feature available in queryForObject instead of concatenating or formatting strings"