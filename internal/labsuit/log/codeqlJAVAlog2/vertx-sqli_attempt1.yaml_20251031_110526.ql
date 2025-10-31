/**
 * @name Vert.x SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if 
 * variables in the SQL statement are not properly sanitized. Use a prepared statements 
 * (java.sql.PreparedStatement) instead. Can obtain using 'connection.prepareStatement'.
 * @kind problem
 * @id java/vertx-sqli
 * @severity Warning
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 *       technology/vertx
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "format" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }
}

class SqlConcatSource extends DataFlow::Node {
  SqlConcatSource() {
    exists(AssignmentExpr assign |
      assign.getRight().toString().matches("String\\s*\\$SQL\\s*=\\s*\\$X\\s*\\+\\s*\\$Y") and
      this.asExpr() = assign.getRight()
    )
  }
}

class SqlExecuteSink extends DataFlow::Node {
  SqlExecuteSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getName().matches("%query%") or
        ma.getMethod().getName().matches("%preparedQuery%") or
        ma.getMethod().getName().matches("%prepare%")
      ) and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlClient") or
        ma.getMethod().getDeclaringType().hasQualifiedName("io.vertx.sqlclient", "SqlConnection")
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class SqlLiteralSanitizer extends DataFlow::Node {
  SqlLiteralSanitizer() {
    exists(Literal l |
      l.getStringValue().matches(/^\"...\"\s*\+\s*\"...\"$/) and
      this.asExpr() = l
    )
  }
}

predicate isTaintedParameter(DataFlow::Node node) {
  exists(Parameter p | node.asParameter() = p)
}

class VertxSqlInjectionFlow extends TaintTracking::Configuration {
  VertxSqlInjectionFlow() { this = "VertxSqlInjectionFlow" }
  
  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlFormatSource or source instanceof SqlConcatSource
  }
  
  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecuteSink
  }
  
  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SqlLiteralSanitizer
  }
  
  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    isTaintedParameter(pred) and pred.asParameter() = succ.asParameter()
  }
}

from VertxSqlInjectionFlow flow, DataFlow::Node source, DataFlow::Node sink
where flow.hasFlow(source, sink)
select sink, "Potential SQL injection via formatted string in $@.", source, 
"this SQL query execution"