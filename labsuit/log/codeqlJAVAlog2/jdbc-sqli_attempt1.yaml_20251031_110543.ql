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
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormatLiteralAnalysis

class StringFormatSource extends DataFlow::Node {
  StringFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }
}

class StringConcatSource extends DataFlow::Node {
  StringConcatSource() {
    exists(AssignmentExpr assign |
      assign.getRight().getType().hasName("String") and
      assign.getLeft().getType().hasName("String") and
      assign.getText().matches("String \\$SQL = \\$X \\+ \\$Y;") and
      this.asExpr() = assign
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      ma.getMethod().getName().matches("^(executeQuery|execute|executeUpdate|executeLargeUpdate|addBatch|nativeSQL)$") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class DirectFormatSink extends DataFlow::Node {
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
}

class DirectConcatSink extends DataFlow::Node {
  DirectConcatSink() {
    exists(BinaryExpr binOp |
      binOp.getOperator() = BinaryOperator.PLUS and
      binOp.getText().matches("\\$X \\+ \\$Y") and
      exists(MethodAccess parent |
        parent.getArgument(_) = binOp and
        parent.getText().matches("\\$S\\.\\$METHOD\\(.*\\+.*,.*\\)")
      ) and
      this.asExpr() = binOp
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(StringLiteral lit |
      lit.getText().matches("^\"\" \\+ \"\"$") and
      this.asExpr() = lit
    )
  }
}

class SafeConcatSanitizer extends DataFlow::Node {
  SafeConcatSanitizer() {
    exists(AssignmentExpr assign |
      assign.getText().matches("String \\$SQL = \".*\" \\+ \".*\";") and
      this.asExpr() = assign
    )
  }
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
    exists(AssignmentExpr assign |
      pred.asExpr() = assign.getRight() and
      succ.asExpr() = assign.getLeft()
    )
  }
}

from DataFlow::Node source, DataFlow::Node sink, JDBCSQLIRuleConfig cfg
where cfg.hasFlow(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead."