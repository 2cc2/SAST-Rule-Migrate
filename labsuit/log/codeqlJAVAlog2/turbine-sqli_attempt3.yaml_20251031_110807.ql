/**
 * @name Turbine SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection 
 *              if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision high
 * @id turbine-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 *       technology/turbine
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class TurbineSQLInjectionConfig extends TaintTracking::Configuration {
  TurbineSQLInjectionConfig() { this = "TurbineSQLInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr().(MethodAccess).getMethod().hasName("format") and
    source.asExpr().(MethodAccess).getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")
    or
    exists(BinaryExpr bin | bin.getOperator() = ADD and source.asExpr() = bin)
    or
    exists(Parameter p | p.getName() = "$SQL" and source.asParameter() = p)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "executeQuery" and
       ma.getMethod().getDeclaringType().hasQualifiedName("", "BasePeer") or
       ma.getMethod().getDeclaringType().hasQualifiedName("", "GroupPeer")) and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Literal l | sanitizer.asExpr() = l and l.getType() instanceof TypeString)
  }
}

from TurbineSQLInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink,
  "Detected a formatted string in a SQL statement. This could lead to SQL injection."