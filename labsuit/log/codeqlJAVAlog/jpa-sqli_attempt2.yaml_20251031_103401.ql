/**
 * @name JPA SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection 
 * if variables in the SQL statement are not properly sanitized. Use prepared statements
 * (java.sql.PreparedStatement) instead.
 * @kind path-problem
 * @problem.severity warning
 * @id java/jpa-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class JpaSqlInjectionConfig extends TaintTracking::Configuration {
  JpaSqlInjectionConfig() { this = "JpaSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      source.asExpr() = ma
    )
    or
    exists(BinaryExpr be |
      be.getOp().toString() = "+" and
      be.getLeftOperand().getType().hasName("String") and
      be.getRightOperand().getType().hasName("String") and
      source.asExpr() = be
    )
    or
    exists(Parameter p |
      p.getType().hasName("String") and
      p.getName().matches("%sql%") and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      (ma.getMethod().getName().matches("createQuery") or
       ma.getMethod().getName().matches("createNativeQuery")) and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence", "EntityManager") and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(StringLiteral sl |
      sl.getValue().regexpMatch("^\"[^\"]*\"\\s*\\+\\s*\"[^\"]*\"$") and
      sanitizer.asExpr() = sl
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      ma.getArgument(_) = pred.asExpr() and
      ma.getQualifier() = succ.asExpr()
    )
  }
}

from JpaSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SQL injection vulnerability due to string concatenation in JPA query"