/**
 * @name JDBC SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection 
 *              if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id java/jdbc-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.Methods

class StringFormatSource extends DataFlow::ExprNode {
  StringFormatSource() { 
    exists(MethodAccess ma | 
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma.getAnArgument()
    )
  }
}

class StringConcatSource extends DataFlow::ExprNode {
  StringConcatSource() {
    exists(AssignExpr assign |
      assign.getDest() instanceof LocalVariable and
      assign.getSource().getType() instanceof TypeString and
      assign.getSource().toString().matches("String \\$SQL = \\$X \\+ \\$Y;") and
      this.asExpr() = assign.getSource()
    )
  }
}

class SqlExecutionSink extends DataFlow::ExprNode {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      ma.getMethod().getName().matches("^(executeQuery|execute|executeUpdate|executeLargeUpdate|addBatch|nativeSQL)$") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class DirectFormatSink extends DataFlow::ExprNode {
  DirectFormatSink() {
    exists(MethodAccess ma, MethodAccess parent |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      parent.getAnArgument() = ma and
      parent.getCode().matches("\\$S\\.\\$METHOD\\(String.format\\(.*\\),.*\\)") and
      this.asExpr() = ma.getAnArgument()
    )
  }
}

class DirectConcatSink extends DataFlow::ExprNode {
  DirectConcatSink() {
    exists(BinaryExpr binExpr, MethodAccess parent |
      binExpr.getOperator() = ADD and
      binExpr.getRightOperand().getType() instanceof TypeString and
      binExpr.getLeftOperand().getType() instanceof TypeString and
      parent.getAnArgument() = binExpr and
      parent.getCode().matches("\\$S\\.\\$METHOD\\(.*\\+.*,.*\\)") and
      this.asExpr() = binExpr
    )
  }
}

class StringLiteralSanitizer extends DataFlow::ExprNode {
  StringLiteralSanitizer() {
    exists(StringLiteral lit |
      lit.toString().matches("^\"\" \\+ \"\"$") and
      this.asExpr() = lit
    )
  }
}

class SafeConcatSanitizer extends DataFlow::ExprNode {
  SafeConcatSanitizer() {
    exists(AssignExpr assign |
      assign.getDest() instanceof LocalVariable and
      assign.getSource().toString().matches("String \\$SQL = \".*\" \\+ \".*\";") and
      this.asExpr() = assign.getSource()
    )
  }
}

class TaintTrackingConfig extends TaintTracking::Configuration {
  TaintTrackingConfig() { this = "JDBC SQL Injection" }

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
    exists(MethodAccess ma, Parameter p |
      ma.getAnArgument() = pred.asExpr() and
      p = ma.getMethod().getAParameter() and
      succ.asParameter() = p
    ) or
    exists(AssignExpr assign |
      assign.getSource() = pred.asExpr() and
      assign.getDest() = succ.asExpr()
    )
  }
}

from DataFlow::Node source, DataFlow::Node sink
where any(TaintTrackingConfig config).hasFlow(source, sink)
select sink, "Potential SQL injection from $@ to $@", source, source.toString(), sink, sink.toString()