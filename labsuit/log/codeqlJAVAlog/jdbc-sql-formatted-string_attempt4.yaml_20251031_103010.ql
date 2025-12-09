/**
 * @name Possible JDBC injection
 * @description Detects unsafe JDBC queries using string formatting/concat
 * @kind problem
 * @problem.severity warning
 * @id java/jdbc-sql-formatted-string
 * @tags security
 *       external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class SqlStringFormatSource extends DataFlow::Node {
  SqlStringFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }
}

class SqlStringConcatSource extends DataFlow::Node {
  SqlStringConcatSource() {
    exists(BinaryOperation bo |
      bo.getOperator() = "+" and
      bo.getLeftOperand().toString().matches("%select%|%update%|%insert%|%delete%") and
      this.asExpr() = bo
    )
  }
}

class SqlStringBuilderAppendSource extends DataFlow::Node {
  SqlStringBuilderAppendSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("append") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      ma.getArgument(0).toString().matches("%select%|%update%|%insert%|%delete%") and
      this.asExpr() = ma
    )
  }
}

class JdbcSink extends DataFlow::Node {
  JdbcSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      (
        ma.getMethod().hasName("queryForObject") or
        ma.getMethod().hasName("queryForList") or
        ma.getMethod().hasName("update") or
        ma.getMethod().hasName("execute") or
        ma.getMethod().hasName("insert")
      ) and
      this.asParameter() = ma.getArgument(0)
    )
  }
}

class ParameterizedQuerySanitizer extends TaintTracking::Sanitizer {
  ParameterizedQuerySanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      ma.getMethod().hasName("queryForObject") and
      ma.getArgument(0).toString().matches("%?%")
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

from JdbcTaintConfig conf, DataFlow::Node source, DataFlow::Node sink
where conf.hasFlow(source, sink)
select sink, "Possible JDBC injection detected. Use the parameterized query feature available " +
  "in queryForObject instead of concatenating or formatting strings: $@",
  source, "Unsafe query construction here"