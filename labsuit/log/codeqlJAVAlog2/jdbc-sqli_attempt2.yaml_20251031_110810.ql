/**
 * @name JDBC SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead.
 * @kind problem
 * @id java/jdbc-sqli
 * @severity Warning
 * @tags security
 *       cwe
 *       owasp-a1
 *       owasp-a3
 */

import java
import codeql.java.dataflow.FlowSources
import codeql.java.dataflow.TaintTracking
import DataFlow::PathGraph

class StringFormatSource extends DataFlow::ExprNode {
  StringFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }

  override predicate exists() { this = this }
}

class StringConcatSource extends DataFlow::ExprNode {
  StringConcatSource() {
    exists(ExprAssign assign |
      assign.getRight().getType().hasName("String") and
      assign.getLeft().getType().hasName("String") and
      assign.getText().matches("String \\$SQL = \\$X \\+ \\$Y;") and
      this.asExpr() = assign
    )
  }

  override predicate exists() { this = this }
}

class SqlExecutionSink extends DataFlow::ExprNode {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      ma.getMethod().getName().matches("^(executeQuery|execute|executeUpdate|executeLargeUpdate|addBatch|nativeSQL)$") and
      this.asExpr() = ma.getArgument(0)
    )
  }

  override predicate exists() { this = this }
}

class DirectFormatSink extends DataFlow::ExprNode {
  DirectFormatSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      exists(MethodAccess parent |
        parent.getArgument(_) = ma and
        parent.getText().matches("\\$S\\.\\$METHOD\\(String.format\\(.*\\),.*\\)")
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }

  override predicate exists() { this = this }
}

class DirectConcatSink extends DataFlow::ExprNode {
  DirectConcatSink() {
    exists(AddExpr binOp |
      binOp.getText().matches("\\$X \\+ \\$Y") and
      exists(MethodAccess parent |
        parent.getArgument(_) = binOp and
        parent.getText().matches("\\$S\\.\\$METHOD\\(.*\\+.*,.*\\)")
      ) and
      this.asExpr() = binOp
    )
  }

  override predicate exists() { this = this }
}

class StringLiteralSanitizer extends DataFlow::ExprNode {
  StringLiteralSanitizer() {
    exists(StringLiteral lit |
      lit.getText().matches("^\"\" \\+ \"\"$") and
      this.asExpr() = lit
    )
  }

  override predicate exists() { this = this }
}

class SafeConcatSanitizer extends DataFlow::ExprNode {
  SafeConcatSanitizer() {
    exists(ExprAssign assign |
      assign.getText().matches("String \\$SQL = \".*\" \\+ \".*\";") and
      this.asExpr() = assign
    )
  }

  override predicate exists() { this = this }
}

class JDBCSQLIRuleConfig extends TaintTracking::Configuration {
  JDBCSQLIRuleConfig() { this = "JDBCSQLIRuleConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or
    source instanceof StringConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink or
    sink instanceof DirectFormatSink or
    sink instanceof DirectConcatSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof StringLiteralSanitizer or
    sanitizer instanceof SafeConcatSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // String propagation (arg->param)
    exists(MethodAccess ma, Parameter p |
      pred.asExpr() = ma.getArgument(_) and
      succ.asParameter() = p and
      p.getMethod() = ma.getMethod()
    ) or
    // Variable assignment propagation
    exists(ExprAssign assign |
      pred.asExpr() = assign.getRight() and
      succ.asExpr() = assign.getLeft()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, JDBCSQLIRuleConfig cfg
where cfg.hasFlowPath(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead."