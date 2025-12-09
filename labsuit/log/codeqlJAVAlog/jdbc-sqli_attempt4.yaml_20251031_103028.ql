/**
 * @id jdbc-sqli
 * @name SQL Injection vulnerability in JDBC
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @severity warning
 * @precision medium
 * @problem.severity warning
 * @security-severity 8.8
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.DataFlow::PathGraph

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
      exists(BinaryOperation binOp |
        binOp.getOperator() instanceof AddOperator and
        assign.getDest().getType() instanceof TypeString and
        assign.getExpr() = binOp and
        this.asExpr() = assign
      )
    )
      or
    exists(AssignmentExpr assign |
      assign.toString().matches("String \\$SQL = \\$X \\+ \\$Y;") and
      this.asExpr() = assign
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      ma.getMethod().getName().matches("executeQuery|execute|executeUpdate|executeLargeUpdate|addBatch|nativeSQL") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(StringLiteral sl |
      sl.toString().matches("^\"\" \\+ \"\"$") and
      this.asExpr() = sl
    )
  }
}

class SafeConcatSanitizer extends DataFlow::Node {
  SafeConcatSanitizer() {
    exists(AssignmentExpr assign |
      assign.toString().matches("String \\$SQL = \".*\" \\+ \".*\";") and
      this.asExpr() = assign
    )
  }
}

class JdbcSqlInjectionConfig extends TaintTracking::Configuration {
  JdbcSqlInjectionConfig() { this = "JdbcSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or
    source instanceof StringConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof StringLiteralSanitizer or
    sanitizer instanceof SafeConcatSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma, Parameter p |
      ma.getArgument(0) = pred.asExpr() and
      p = ma.getMethod().getAParameter() and
      succ.asParameter() = p
    )
      or
    exists(AssignmentExpr assign |
      assign.getExpr() = pred.asExpr() and
      assign.getDest() = succ.asExpr()
    )
  }
}

from JdbcSqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink,
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead."