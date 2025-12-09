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
 *       technology/jdbc
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import DataFlow::PathGraph

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
      assign.getTarget().getType().hasName("String") and
      assign.getExpr().(BinaryOperation).getOperator().toString().matches("\\+") and
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
    exists(StringLiteral lit |
      lit.getText().matches("^\"\" \\+ \"\"$") and
      this.asExpr() = lit
    )
  }
}

class SafeConcatSanitizer extends DataFlow::Node {
  SafeConcatSanitizer() {
    exists(AssignmentExpr assign |
      assign.getTarget().getType().hasName("String") and
      assign.getExpr().toString().matches("\".*\" \\+ \".*\"") and
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
      ma.getMethod().getNumberOfParameters() > 0 and
      ma.getArgument(0) = pred.asExpr() and
      p = ma.getMethod().getParameter(0) and
      succ.asParameter() = p
    ) or
    exists(AssignmentExpr assign |
      assign.getTarget() = pred.asExpr() and
      assign.getExpr() = succ.asExpr()
    )
  }
}

from JdbcSqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead."