/**
 * @name JDBC SQL Injection
 * @description Detected a formatted string in a SQL statement.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id java/jdbc-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.stringtemplate.FormattedString

class StringFormatSource extends DataFlow::Node {
  StringFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasName("String")
    )
  }
}

class StringConcatSource extends DataFlow::Node {
  StringConcatSource() {
    exists(AssignmentExpr assign |
      assign.getDest().getType().hasName("String") and
      assign.getSource().getType().hasName("String") and
      assign.getSource().toString().matches("%SQL = %X + %Y")
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasName("Statement") and
      ma.getMethod().getName().matches("executeQuery|execute|executeUpdate|executeLargeUpdate|addBatch|nativeSQL") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class DirectFormatSink extends DataFlow::Node {
  DirectFormatSink() {
    exists(MethodAccess ma, MethodAccess parent |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasName("String") and
      parent.getMethod().getDeclaringType().hasName("Statement") and
      parent.getParent()*.toString().matches("%S.%METHOD(String.format(.*),.*)")
    )
  }
}

class DirectConcatSink extends DataFlow::Node {
  DirectConcatSink() {
    exists(BinaryExpr binOp |
      binOp.getOp() = "+" and
      binOp.getParent()*.toString().matches("%S.%METHOD(.*+.*,.*)")
    )
  }
}

class StringLiteralSanitizer extends Sanitizer {
  StringLiteralSanitizer() {
    exists(Literal literal |
      literal.getStringValue() = "\"\" + \"\""
    )
  }
}

class SafeConcatSanitizer extends Sanitizer {
  SafeConcatSanitizer() {
    exists(AssignmentExpr assign |
      assign.getDest().getType().hasName("String") and
      assign.getSource().toString().matches("String %SQL = \".*\" + \".*\"")
    )
  }
}

class JdbcSqlInjectionConfig extends TaintTracking::Configuration {
  JdbcSqlInjectionConfig() { this = "JdbcSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or source instanceof StringConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink or sink instanceof DirectFormatSink or sink instanceof DirectConcatSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof StringLiteralSanitizer or sanitizer instanceof SafeConcatSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Method m, Parameter p |
      pred.asParameter() = source and
      succ.asParameter() = p and
      m.getAParameter() = p
    )
    or
    exists(AssignmentExpr assign |
      succ.asExpr() = assign.getDest() and
      pred.asExpr() = assign.getSource()
    )
  }
}

from JdbcSqlInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'."