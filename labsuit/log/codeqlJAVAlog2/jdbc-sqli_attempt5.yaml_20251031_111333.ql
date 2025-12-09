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
import semmle.code.java.Expr
import semmle.code.java.VarAccess

class StringFormatSource extends DataFlow::Node {
  StringFormatSource() { 
    exists(MethodAccess m | 
      m.getMethod().hasName("format") and
      m.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = m.getArgument(0)
    )
  }
}

class StringConcatSource extends DataFlow::Node {
  StringConcatSource() {
    exists(VarAccess assign |
      assign.getVariable().isLocal() and
      assign.getVariable().getType().hasName("string") and
      assign.getParent().toString().matches("String \\$SQL = \\$X \\+ \\$Y;") and
      this.asExpr() = assign.getExpr()
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess m |
      m.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      m.getMethod().getName().matches("^(executeQuery|execute|executeUpdate|executeLargeUpdate|addBatch|nativeSQL)$") and
      this.asExpr() = m.getArgument(0)
    )
  }
}

class DirectFormatSink extends DataFlow::Node {
  DirectFormatSink() {
    exists(MethodAccess fmt, MethodAccess parent |
      fmt.getMethod().hasName("format") and
      fmt.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      parent.getAnArgument() = fmt and
      parent.toString().matches("\\$S\\.\\$METHOD\\(String.format\\(.*\\),.*\\)") and
      this.asExpr() = fmt.getArgument(0)
    )
  }
}

class DirectConcatSink extends DataFlow::Node {
  DirectConcatSink() {
    exists(BinaryOperation e, MethodAccess parent |
      e.getOperator() = "+" and
      parent.getAnArgument() = e and
      parent.toString().matches("\\$S\\.\\$METHOD\\(.*\\+.*,.*\\)") and
      this.asExpr() = e
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(LiteralExpr lit |
      lit.toString().matches("^\"\" \\+ \"\"$") and
      this.asExpr() = lit
    )
  }
}

class SafeConcatSanitizer extends DataFlow::Node {
  SafeConcatSanitizer() {
    exists(VarAccess assign |
      assign.getVariable().isLocal() and
      assign.getParent().toString().matches("String \\$SQL = \".*\" \\+ \".*\";") and
      this.asExpr() = assign.getExpr()
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
    exists(MethodAccess m, Parameter p |
      m.getAnArgument() = pred.asExpr() and
      p = m.getMethod().getAParameter() and
      succ.asParameter() = p
    ) or
    exists(VarAccess assign |
      assign.getExpr() = pred.asExpr() and
      assign.getVariable() = succ.asVariable()
    )
  }
}

from DataFlow::Node source, DataFlow::Node sink, TaintTrackingConfig config
where config.hasFlow(source, sink)
select sink, "Potential SQL injection from $@ to $@", source, source.toString(), sink, sink.toString()