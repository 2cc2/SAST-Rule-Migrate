/**
 * @id jdbc-sql-formatted-string
 * @kind path-problem
 * @problem.severity WARNING
 * @message Possible JDBC injection detected. Use the parameterized query feature available in queryForObject instead of concatenating or formatting strings: 'jdbc.queryForObject("select * from table where name = ?", Integer.class, parameterName);'
 */
import semmle.code.java.Methods
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.Expr
import semmle.code.java.expr.BinaryExpr

// Sources
predicate isSQLStringFormatting(Method m) {
  m.getName() = "format" and
  m.getDeclaringType().hasQualifiedName("java.lang", "String")
}

predicate isSQLStringConcat(BinaryExpr be) {
  be instanceof BinaryExpr and
  be.getRightOperand().getStringValue().regexpMatch(".*select.*|.*update.*|.*insert.*|.*delete.*")
}

predicate isSQLStringBuilderAppend(Method m) {
  m.getName() = "append" and
  m.getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
  m.getCall().getArgument(0).getStringValue().regexpMatch(".*select.*|.*update.*|.*insert.*|.*delete.*")
}

// Sinks
predicate isJdbcQuerySink(Method m) {
  m.getName() in ["queryForObject", "queryForList", "update", "execute", "insert"] and
  m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate")
}

// Sanitizer
predicate isParameterizedQuery(Method m) {
  m.getName() = "queryForObject" and
  m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
  m.getCall().getArgument(0).getStringValue().regexpMatch(".*\\?.*")
}

// Taint configuration
class SQLInjectionConfig extends TaintTracking::Configuration {
  SQLInjectionConfig() { this = "SQLInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m |
      (isSQLStringFormatting(m) or isSQLStringConcat(source.asExpr()) or isSQLStringBuilderAppend(m)) and
      source.asExpr() = m.getCall()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Method m |
      isJdbcQuerySink(m) and
      sink.asExpr() = m.getCall().getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Method m |
      isParameterizedQuery(m) and
      sanitizer.asExpr() = m.getCall().getArgument(0)
    )
  }
}

from SQLInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Possible JDBC injection detected. Use parameterized queries instead of string concatenation/formatting."