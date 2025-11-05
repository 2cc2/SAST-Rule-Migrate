/**
 * @name JDO SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead.
 * @kind path-problem
 * @problem.severity warning
 * @id java/jdo-sqli
 * @tags security
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class SQLFormatSource extends DataFlow::ExprNode {
  SQLFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") |
      this.asExpr() = ma
    )
  }
}

class SQLConcatSource extends DataFlow::ExprNode {
  SQLConcatSource() {
    exists(AssignmentExpr assign |
      assign.getTarget().toString().matches("%SQL%") and
      assign.getSource().toString().matches("%+%") |
      this.asExpr() = assign.getSource()
    )
  }
}

class SQLParamSource extends DataFlow::ParameterNode {
  SQLParamSource() {
    this.getParameter().getName().matches("%SQL%") and
    exists(CallExpr ce |
      ce.getArgument(this.getParameter().getIndex()) = this.getParameter().getAnAccess()
    )
  }
}

class JDOQuerySink extends DataFlow::ExprNode {
  JDOQuerySink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("setFilter") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "Query") and
      ma.getArgument(0) = this.asExpr()
    ) or
    exists(MethodAccess ma |
      ma.getMethod().hasName("setGrouping") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "Query") and
      ma.getArgument(0) = this.asExpr()
    )
  }
}

class PMNewQuerySink extends DataFlow::ExprNode {
  PMNewQuerySink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("newQuery") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "PersistenceManager") and
      ma.getArgument(1) = this.asExpr()
    )
  }
}

class SafeConcatSanitizer extends DataFlow::ExprNode {
  SafeConcatSanitizer() {
    exists(AssignmentExpr assign |
      assign.getSource().toString().matches("\"%\" + \"%\"") |
      this.asExpr() = assign.getSource()
    )
  }
}

class SafeParamSanitizer extends DataFlow::ParameterNode {
  SafeParamSanitizer() {
    this.getParameter().getAnAccess().toString().matches("\"%\"")
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "JDO_SQLi" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SQLFormatSource or
    source instanceof SQLConcatSource or
    source instanceof SQLParamSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof JDOQuerySink or
    sink instanceof PMNewQuerySink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SafeConcatSanitizer or
    sanitizer instanceof SafeParamSanitizer
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink,
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements instead."