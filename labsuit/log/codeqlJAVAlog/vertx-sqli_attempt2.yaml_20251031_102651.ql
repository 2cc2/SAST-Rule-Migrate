/**
 * @name Vert.x SQL Injection
 * @description Detected a formatted string in a SQL statement. 
 * This could lead to SQL injection if variables in the SQL statement are not properly sanitized. 
 * Use prepared statements (java.sql.PreparedStatement) instead.
 * @id vertx-sqli
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-089
 *       external/cwe/cwe-564
 *       external/owasp/a01
 *       external/owasp/a03
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.StringOperations
import DataFlow::PathGraph

class FormattedSqlSource extends DataFlow::ExprNode {
  FormattedSqlSource() {
    exists(MethodCall mc |
      mc.getMethod().getName() = "format" and
      mc.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = mc
    )
  }
}

class ConcatSqlSource extends DataFlow::ExprNode {
  ConcatSqlSource() {
    exists(AssignExpr assign |
      assign.getRValue().toString().matches("String\\s*\\$SQL\\s*=\\s*\\$X\\s*\\+\\s*\\$Y") and
      this.asExpr() = assign.getRValue()
    )
  }
}

class SqlClientSink extends DataFlow::ExprNode {
  SqlClientSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().getName().matches("query|preparedQuery|prepare") and
        mc.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlClient")
      ) or
      (
        mc.getMethod().getName().matches("query|preparedQuery|prepare") and
        mc.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlConnection")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

class SqlSanitizer extends DataFlow::Barrier {
  SqlSanitizer() {
    exists(StringLiteral sl |
      sl.getStringValue().matches("^\\\"...\\\"\\s*\\+\\s*\\\"...\\\"$") and
      this.asExpr() = sl
    )
  }
}

class VertxSqlConfig extends TaintTracking::Configuration {
  VertxSqlConfig() { this = "VertxSqlConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof FormattedSqlSource or source instanceof ConcatSqlSource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlClientSink
  }
  
  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SqlSanitizer
  }
  
  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodCall mc, Parameter p |
      mc.getArgument(p.getIndex()) = node1.asExpr() and
      p = node2.asParameter()
    )
  }
}

from VertxSqlConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SQL injection using formatted string in Vert.x SQL client"