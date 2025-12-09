/**
 * @name JDO SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection 
 * if variables in the SQL statement are not properly sanitized. Use a prepared statements 
 * (java.sql.PreparedStatement) instead.
 * @kind problem
 * @problem.severity warning
 * @id java/jdo-sqli
 * @tags security
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

class JdoSqlInjectionConfig extends TaintTracking::Configuration {
  JdoSqlInjectionConfig() { this = "JdoSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Sources from String.format calls
    exists(MethodAccess ma | 
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") |
      source.asExpr() = ma
    )
    or
    // Sources from SQL string concatenation assignments
    exists(AssignmentExpr assign | 
      assign.getRightOperand().getType().hasName("String") and
      assign.getCode().matches("%SQL = %X + %Y%") |
      source.asExpr() = assign
    )
    or
    // Sources from SQL parameters
    exists(MethodParameter mp |
      mp.getName().matches("%SQL%") |
      source = DataFlow::parameterNode(mp)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // Sinks in javax.jdo.Query methods
    exists(MethodAccess ma |
      (
        ma.getMethod().hasName("setFilter") and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "Query") and
        sink.asExpr() = ma.getArgument(0)
      )
      or
      (
        ma.getMethod().hasName("setGrouping") and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "Query") and
        sink.asExpr() = ma.getArgument(0)
      )
      or
      (
        ma.getMethod().hasName("newQuery") and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "PersistenceManager") and
        sink.asExpr() = ma.getArgument(1)
      )
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // Safe string literal concatenation
    exists(AssignmentExpr assign |
      assign.getCode().matches("$SQL = \"...\" + \"...\"") |
      node.asExpr() = assign
    )
    or
    // Safe string literal parameters
    exists(MethodParameter mp |
      mp.getInitializer().getCode().matches("\"...\"") |
      node = DataFlow::parameterNode(mp)
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Propagate taint through argument to parameter flow
    TaintTracking::localTaintStep(node1, node2)
  }
}

from JdoSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source.getNode(), 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables " +
  "in the SQL statement are not properly sanitized. Use a prepared statements " +
  "(java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using " +
  "'connection.prepareStatement'."