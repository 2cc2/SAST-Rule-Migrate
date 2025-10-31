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
import codeql.java.dataflow.FlowSources
import codeql.java.dataflow.TaintTracking
import codeql.java.dataflow.DataFlow
import codeql.java.Methods
import codeql.java.expr.Expr
import codeql.java.vars.VariableAccess

class StringFormatSource extends TaintTracking::SourceNode {
  StringFormatSource() { 
    exists(Method m | 
      m.hasName("format") and
      m.getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = m.getACall().getAnArgument()
    )
  }
}

class StringConcatSource extends TaintTracking::SourceNode {
  StringConcatSource() {
    exists(VariableAccess assign |
      assign.getVariable().isLocal() and
      assign.getExpr().getType() instanceof PrimitiveType and
      assign.getExpr().getType().hasName("string") and
      assign.getExpr().toString().matches("String \\$SQL = \\$X \\+ \\$Y;") and
      this.asExpr() = assign.getExpr()
    )
  }
}

class SqlExecutionSink extends TaintTracking::SinkNode {
  SqlExecutionSink() {
    exists(Method m |
      m.getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      m.getName().matches("^(executeQuery|execute|executeUpdate|executeLargeUpdate|addBatch|nativeSQL)$") and
      this.asExpr() = m.getACall().getArgument(0)
    )
  }
}

class DirectFormatSink extends TaintTracking::SinkNode {
  DirectFormatSink() {
    exists(Method fmt, Method parent |
      fmt.hasName("format") and
      fmt.getDeclaringType().hasQualifiedName("java.lang", "String") and
      parent.getACall().getAnArgument() = fmt.getACall() and
      parent.getACall().toString().matches("\\$S\\.\\$METHOD\\(String.format\\(.*\\),.*\\)") and
      this.asExpr() = fmt.getACall().getAnArgument()
    )
  }
}

class DirectConcatSink extends TaintTracking::SinkNode {
  DirectConcatSink() {
    exists(Expr e, Method parent |
      e instanceof BinaryExpr and
      e.asExpr().getOperator() = "+" and
      parent.getACall().getAnArgument() = e and
      parent.getACall().toString().matches("\\$S\\.\\$METHOD\\(.*\\+.*,.*\\)") and
      this.asExpr() = e
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(Literal lit |
      lit.toString().matches("^\"\" \\+ \"\"$") and
      this.asExpr() = lit
    )
  }
}

class SafeConcatSanitizer extends DataFlow::Node {
  SafeConcatSanitizer() {
    exists(VariableAccess assign |
      assign.getVariable().isLocal() and
      assign.getExpr().toString().matches("String \\$SQL = \".*\" \\+ \".*\";") and
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
    exists(Method m, Parameter p |
      m.getACall().getAnArgument() = pred.asExpr() and
      p = m.getAParameter() and
      succ.asParameter() = p
    ) or
    exists(VariableAccess assign |
      assign.getExpr() = pred.asExpr() and
      assign.getVariable() = succ.asVariable()
    )
  }
}

from DataFlow::Node source, DataFlow::Node sink, TaintTrackingConfig config
where config.hasFlow(source, sink)
select sink, "Potential SQL injection from $@ to $@", source, source.toString(), sink, sink.toString()