/**
 * @name JPA SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection 
 *              if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id java/jpa-sqli
 * @tags security
 *       cwe: "CWE-89"
 *       owasp: "A01:2017"
 *       owasp: "A03:2021"
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class JpaSqlInjectionConfig extends TaintTracking::Configuration {
  JpaSqlInjectionConfig() { this = "JpaSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Source 1: String.format calls
    exists(MethodAccess ma | 
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      source.asExpr() = ma
    )
    or
    // Source 2: String concatenation operations
    exists(BinaryExpr bin |
      bin.getOperator().toString() = "+" and
      bin.getLeftOperand().getType().hasName("String") and
      bin.getRightOperand().getType().hasName("String") and
      source.asExpr() = bin
    )
    or
    // Source 3: Method parameters with "sql" in name
    exists(Parameter p |
      p.getType().hasName("String") and
      p.getName().matches("%sql%") and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("createQuery%") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence", "EntityManager") and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(StringLiteral lit |
      lit.getValue().matches("^\"[^\"]*\"\\s*\\+\\s*\"[^\"]*\"$") and
      sanitizer.asExpr() = lit
    )
  }
}

from JpaSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead."