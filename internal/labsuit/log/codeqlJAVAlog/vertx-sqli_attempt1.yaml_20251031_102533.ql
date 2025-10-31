/**
 * @name vertx-sqli
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection 
 * if variables in the SQL statement are not properly sanitized. Use a prepared statements 
 * (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.
 * @kind problem
 * @problem.severity warning
 * @id java/vertx-sqli
 * @tags security
 *       cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
 *       owasp: "A01:2017 - Injection"
 *       owasp: "A03:2021 - Injection"
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat

class FormattedSqlSource extends DataFlow::ExprNode {
  FormattedSqlSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasName("String") and
      this.asExpr() = ma
    )
  }
}

class ConcatSqlAssignmentSource extends DataFlow::ExprNode {
  ConcatSqlAssignmentSource() {
    exists(AssignmentExpr assign, LocalVariableDeclaration lvd |
      assign.getDest().(VariableAccess).getTarget() = lvd.getVariable() and
      lvd.getType().hasName("String") and
      lvd.getVariable().getName().matches("%SQL%") and
      this.asExpr() = assign.getSource()
    )
  }
}

class SqlClientSink extends DataFlow::ExprNode {
  SqlClientSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().hasName("query") or
        ma.getMethod().hasName("preparedQuery") or
        ma.getMethod().hasName("prepare")
      ) and
      (
        ma.getMethod().getDeclaringType().hasName("SqlClient") or
        ma.getMethod().getDeclaringType().hasName("SqlConnection")
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class LiteralSanitizer extends BarrierGuard {
  override predicate checks(Expr e, boolean branch) {
    exists(StringLiteral lit |
      lit.getValue().matches("\"%\" + \"%\"") and
      e = lit
    )
  }
}

class VertxSQLiConfig extends TaintTracking::Configuration {
  VertxSQLiConfig() { this = "VertxSQLiConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof FormattedSqlSource or
    source instanceof ConcatSqlAssignmentSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlClientSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node.getType() instanceof LiteralSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma, Parameter p |
      ma.getArgument(_) = pred.asExpr() and
      p = ma.getMethod().getAParameter() and
      succ.asParameter() = p
    )
  }
}

from VertxSQLiConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential SQL injection vulnerability due to use of formatted string in SQL statement"