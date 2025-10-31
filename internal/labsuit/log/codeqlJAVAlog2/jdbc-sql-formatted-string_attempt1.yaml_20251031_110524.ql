/**
 * @id jdbc-sql-formatted-string
 * @severity WARNING
 * @message Possible JDBC injection detected. Use the parameterized query feature available in queryForObject instead of concatenating or formatting strings: 'jdbc.queryForObject("select * from table where name = ?", Integer.class, parameterName);'
 */
import java

// Sources
predicate isSQLStringFormatting(MethodAccess ma) {
  ma.getMethod().hasName("format") and
  ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")
}

predicate isSQLStringConcat(MethodAccess ma) {
  ma instanceof AddExpr and
  ma.getRightOperand().toString().regexpMatch(".*select.*|.*update.*|.*insert.*|.*delete.*")
}

predicate isSQLStringBuilderAppend(MethodAccess ma) {
  ma.getMethod().hasName("append") and
  ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
  ma.getArgument(0).toString().regexpMatch(".*select.*|.*update.*|.*insert.*|.*delete.*")
}

// Sinks
predicate isJdbcQuerySink(MethodAccess ma) {
  ma.getMethod().hasName(["queryForObject", "queryForList", "update", "execute", "insert"]) and
  ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate")
}

// Sanitizer
predicate isParameterizedQuery(MethodAccess ma) {
  ma.getMethod().hasName("queryForObject") and
  ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
  ma.getArgument(0).toString().regexpMatch(".*\\?.*")
}

// Taint configuration
class SQLInjectionConfig extends TaintTracking::Configuration {
  SQLInjectionConfig() { this = "SQLInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      (isSQLStringFormatting(ma) or isSQLStringConcat(ma) or isSQLStringBuilderAppend(ma)) and
      source.asExpr() = ma
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      isJdbcQuerySink(ma) and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodAccess ma |
      isParameterizedQuery(ma) and
      sanitizer.asExpr() = ma.getArgument(0)
    )
  }
}

from SQLInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Possible JDBC injection detected. Use parameterized queries instead of string concatenation/formatting."