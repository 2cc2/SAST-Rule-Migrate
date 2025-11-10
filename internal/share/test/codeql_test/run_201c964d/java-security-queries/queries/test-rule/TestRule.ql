/**
 * @name Tainted SQL Injection in AWS Lambda
 * @description Detected SQL statement that is tainted by event object. This could lead to SQL
 *              injection if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id java/tainted-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/cwe/cwe-564
 *       owasp-a01
 *       owasp-a03
 *       technology/sql
 *       technology/java
 *       technology/aws-lambda
 */

import java
import semmle.code.java.dataflow.TaintTracking

class LambdaEventHandler extends Method {
  LambdaEventHandler() {
    this.getAParameter().getType().getName().matches("InputStream|%EVENT%") and
    (
      this.getName().matches("handleRequest") or
      this.getName().matches("handleEvent")
    )
  }
}

class TaintedSqlFlowConfiguration extends TaintTracking::Configuration {
  TaintedSqlFlowConfiguration() { this = "TaintedSqlFlowConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m | 
      m instanceof LambdaEventHandler and
      source.asParameter() = m.getAParameter()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Expr ma, Method meth |
      (
        ma instanceof MethodAccess and
        (meth = ma.(MethodAccess).getMethod()) and
        meth.getName().matches("execute|query|executeUpdate|batchUpdate") and
        ma.(MethodAccess).getArgument(0) = sink.asExpr() and
        sink.getType() instanceof TypeString
      )
      or
      exists(Method m | 
        m.getDeclaringType().hasQualifiedName("java.sql", "Statement") and
        ma instanceof MethodAccess and
        ma.(MethodAccess).getMethod() = m and
        ma.(MethodAccess).getArgument(0) = sink.asExpr()
      )
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedSqlFlowConfiguration config
where config.hasFlowPath(source, sink)
select sink, source, sink,
  "Potential SQL injection from Lambda event parameter to $@.",
  source.getNode(), "user input",
  sink.getNode(), "SQL query execution"