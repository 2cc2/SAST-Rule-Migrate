/**
 * @name Turbine SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead.
 * @kind problem
 * @id java/turbine-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringOps

class TurbineSqlInjection extends TaintTracking::Configuration {
  TurbineSqlInjection() { this = "TurbineSqlInjection" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "format" and ma.getMethod().getDeclaringType().toString() = "String") or
      exists(Expr e | e = source.asExpr() | e instanceof AddExpr)
    )
    or
    exists(Parameter p | p.getName() = "$SQL" and source.asParameter() = p)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "executeQuery" and
      (ma.getMethod().getDeclaringType().getName() = "BasePeer" or 
       ma.getMethod().getDeclaringType().getName() = "GroupPeer") and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Literal l | l = sanitizer.asExpr() | l.isStringLiteral())
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma |
      node1.asExpr() = ma.getAnArgument() and
      node2.asParameter() = ma.getMethod().getAParameter()
    )
  }
}

from TurbineSqlInjection config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), "Detected a formatted string in a SQL statement. This could lead to SQL injection. Use prepared statements instead."