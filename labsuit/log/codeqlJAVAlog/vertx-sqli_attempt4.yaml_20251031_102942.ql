/**
 * @name Vert.x SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables 
 *              in the SQL statement are not properly sanitized. Use prepared statements instead.
 * @kind path-problem
 * @problem.severity warning
 * @id java/vertx-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import java
import DataFlow::PathGraph
import DataFlow::TaintTracking
import DataFlow::StringOperations

class FormattedSqlSource extends DataFlow::Node {
  FormattedSqlSource() {
    exists(MethodCall call |
      call.getMethod().hasQualifiedName("java.lang", "String", "format") and
      this = call.asNode()
    )
  }
}

class ConcatSqlSource extends DataFlow::Node {
  ConcatSqlSource() {
    exists(AssignmentNode assign |
      assign.getTarget().getType() instanceof StringType and
      assign.getTarget().toString().matches("String \\$SQL = \\$X \\+ \\$Y") and
      this = assign.asNode()
    )
  }
}

class SqlClientSink extends DataFlow::Node {
  SqlClientSink() {
    exists(MethodCall call |
      (
        call.getMethod().hasQualifiedName("io.vertx.sqlclient", "SqlClient", ["query", "preparedQuery", "prepare"]) or
        call.getMethod().hasQualifiedName("io.vertx.sqlclient", "SqlConnection", ["query", "preparedQuery", "prepare"])
      ) and
      this = call.getArgument(0).asNode()
    )
  }
}

class SqlSanitizer extends DataFlow::Node {
  SqlSanitizer() {
    exists(LiteralNode lit |
      lit.getValue().matches("^\\\"...\\\" \\+ \\\"...\\\"$") and
      this = lit.asNode()
    )
  }
}

class VertxSqlInjectionConfig extends TaintTracking::Configuration {
  VertxSqlInjectionConfig() { this = "VertxSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof FormattedSqlSource or source instanceof ConcatSqlSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlClientSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SqlSanitizer
  }
}

from VertxSqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Potential SQL injection vuln from $@ to $@", source, "user input", sink, "SQL query execution"