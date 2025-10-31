/**
 * @name Vert.x SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection.
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id java/vertx-sqli
 * @tags security
 *       cwe/cwe-89
 *       owasp/a01
 *       owasp/a03
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringOperations
import DataFlow::PathGraph

class FormattedSqlSource extends DataFlow::ExprNode {
  FormattedSqlSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }
}

class ConcatSqlSource extends DataFlow::ExprNode {
  ConcatSqlSource() {
    exists(AssignmentExpr ae |
      ae.getDest().toString().matches("String \\$SQL = \\$X [+] \\$Y") and
      this.asExpr() = ae.getDest()
    )
  }
}

class SqlClientSink extends DataFlow::ExprNode {
  SqlClientSink() {
    exists(MethodAccess ma |
      (ma.getMethod().hasName("query") or
       ma.getMethod().hasName("preparedQuery") or
       ma.getMethod().hasName("prepare")) and
      (ma.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlClient") or
       ma.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlConnection")) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class SqlSanitizer extends DataFlow::BarrierGuard, DataFlow::ExprNode {
  SqlSanitizer() {
    exists(Literal lit |
      lit.getStringValue().matches("^\"...\" [+] \"...\"$") and
      this.asExpr() = lit
    )
  }
}

class VertxSqliConfig extends TaintTracking::Configuration {
  VertxSqliConfig() { this = "VertxSqliConfig" }

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
    exists(MethodAccess ma, Parameter p |
      ma.getArgument(0) = node1.asExpr() and
      p = ma.getMethod().getAParameter() and
      node2.asParameter() = p
    )
  }
}

from VertxSqliConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'."