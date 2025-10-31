/**
 * @name Possible JDBC injection detected
 * @description Use the parameterized query feature available in queryForObject instead of concatenating or formatting strings
 * @kind problem
 * @id java/jdbc-sql-formatted-string
 * @tags security
 * @severity Warning
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import semmle.code.java.frameworks.spring.JdbcOperations

class SqlStringFormatSource extends DataFlow::Node {
  SqlStringFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("java.lang.String", "format") and
      this.asExpr() = ma
    )
  }
}

class SqlStringConcatSource extends DataFlow::Node {
  SqlStringConcatSource() {
    exists(BinaryExpr be |
      be.getOp() = "+" and
      regexpMatch(be.getLeftOperand().toString(), ".*select.*|.*update.*|.*insert.*|.*delete.*") and
      this.asExpr() = be
    )
  }
}

class SqlStringBuilderAppendSource extends DataFlow::Node {
  SqlStringBuilderAppendSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("java.lang.StringBuilder", "append") and
      regexpMatch(ma.getArgument(0).toString(), ".*select.*|.*update.*|.*insert.*|.*delete.*") and
      this.asExpr() = ma
    )
  }
}

class JdbcQuerySink extends DataFlow::Node {
  JdbcQuerySink() {
    exists(MethodAccess ma |
      (ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", "queryForObject") or
       ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", "queryForList") or
       ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", "update") or
       ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", "execute") or
       ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", "insert")) and
      this.asParameter() = ma.getArgument(0)
    )
  }
}

class ParameterizedQuerySanitizer extends TaintTracking::Sanitizer {
  override predicate isSanitizer(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", "queryForObject") and
      regexpMatch(ma.getArgument(0).toString(), "\\?") and
      node.asParameter() = ma.getArgument(0)
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
    sink instanceof JdbcQuerySink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof ParameterizedQuerySanitizer
  }
}

from DataFlow::Node source, DataFlow::Node sink, JdbcTaintConfig config
where config.hasFlow(source, sink)
select sink, "Possible JDBC injection detected. Use the parameterized query feature available in queryForObject instead of concatenating or formatting strings."