/**
 * @name Possible JDBC injection detected
 * @description Use the parameterized query feature available in queryForObject instead of concatenating or formatting strings 
 * @kind problem
 * @id java/jdbc-sql-formatted-string
 * @severity Warning
 * @tags security
 *       java
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import semmle.code.java.frameworks.spring.JdbcOperations

class SqlStringFormatSource extends DataFlow::Node {
  SqlStringFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasName("String") and
      ma.getMethod().getDeclaringType().getPackage().hasName("java.lang") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class SqlStringConcatSource extends DataFlow::Node {
  SqlStringConcatSource() {
    exists(BinaryExpr be |
      be.getOperator() = "+" and
      exists(be.getLeft().getStringValue() |
        regexpMatches(_, ".*select.*|.*update.*|.*insert.*|.*delete.*")
      ) and
      this.asExpr() = be.getLeft()
    )
  }
}

class SqlStringBuilderAppendSource extends DataFlow::Node {
  SqlStringBuilderAppendSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("append") and
      ma.getMethod().getDeclaringType().hasName("StringBuilder") and
      exists(ma.getArgument(0).getStringValue() |
        regexpMatches(_, ".*select.*|.*update.*|.*insert.*|.*delete.*")
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class JdbcQuerySink extends DataFlow::Node {
  JdbcQuerySink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      (
        ma.getMethod().hasName("queryForObject") or
        ma.getMethod().hasName("queryForList") or
        ma.getMethod().hasName("update") or
        ma.getMethod().hasName("execute") or
        ma.getMethod().hasName("insert")
      ) and
      this.asExpr() = ma.getArgument(0)
    ) and not exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      ma.getMethod().hasName("queryForObject") and
      exists(ma.getArgument(0).getStringValue() |
        regexpMatches(_, "\\?")
      )
    )
  }
}

class JdbcTaintConfiguration extends TaintTracking::Configuration {
  JdbcTaintConfiguration() { this = "JdbcTaintConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlStringFormatSource or
    source instanceof SqlStringConcatSource or
    source instanceof SqlStringBuilderAppendSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof JdbcQuerySink
  }
}

from JdbcTaintConfiguration config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Possible JDBC injection detected. Use the parameterized query feature available in queryForObject instead of concatenating or formatting strings: 'jdbc.queryForObject(\"select * from table where name = ?\", Integer.class, parameterName);'"