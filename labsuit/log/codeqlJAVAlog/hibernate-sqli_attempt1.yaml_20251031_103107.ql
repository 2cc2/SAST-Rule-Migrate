/**
 * @name hibernate-sqli
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.
 * @severity Warning
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       java
 *       external/cwe/cwe-089
 *       external/cwe/cwe-564
 * @id java/hibernate-sqli
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

// Source definitions
predicate isStringFormat(DataFlow::Node source) {
  exists(MethodAccess ma |
    ma.getMethod().getName() = "format" and
    ma.getMethod().getDeclaringType().hasName("String") and
    source.asExpr() = ma
  )
}

predicate isStringConcatAssignment(DataFlow::Node source) {
  exists(AssignmentExpr assign |
    assign.getTarget().getType().hasName("String") and
    exists(MethodAccess ma | ma.getMethod().getName().regexpMatch("[+]") |
      ma.getAnOperand() = assign.getTarget().getAChild() or
      ma.getAnOperand() = assign.getValue().getAChild()
    ) and
    source.asExpr() = assign
  )
}

// Sink definitions
predicate isSqlRestrictionCall(DataFlow::Node sink) {
  exists(MethodAccess ma |
    ma.getMethod().getName() = "sqlRestriction" and
    ma.getMethod().getDeclaringType().hasName("Restrictions") and
    sink.asArgument(0) = ma.getArgument(0)
  )
}

predicate isSessionQueryCall(DataFlow::Node sink) {
  exists(MethodAccess ma |
    ma.getMethod().getName().regexpMatch("^(createQuery|createSQLQuery)$") and
    ma.getMethod().getDeclaringType().hasName("Session") and
    sink.asArgument(0) = ma.getArgument(0)
  )
}

// Sanitizer definition
predicate isLiteralStringConcat(DataFlow::Node node) {
  exists(AssignmentExpr assign |
    assign.getTarget().getType().hasName("String") and
    exists(MethodAccess ma | ma.getMethod().getName().regexpMatch("[+]") |
      all(ma.getAnOperand() |
        ma.getAnOperand().getType() instanceof Literal or
        (ma.getAnOperand() instanceof StringLiteral)
      )
    ) and
    node.asExpr() = assign
  )
}

// Taint tracking configuration
class HibernateSqliConfig extends TaintTracking::Configuration {
  HibernateSqliConfig() { this = "HibernateSqliConfig" }

  override predicate isSource(DataFlow::Node source) {
    isStringFormat(source) or
    isStringConcatAssignment(source)
  }

  override predicate isSink(DataFlow::Node sink) {
    isSqlRestrictionCall(sink) or
    isSessionQueryCall(sink)
  }

  override predicate isSanitizer(DataFlow::Node node) {
    isLiteralStringConcat(node)
  }
}

from HibernateSqliConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized.", 
  source, sink,
  "Potential SQL injection vulnerability due to use of string concatenation in Hibernate query."