/**
 * @name Formatted SQL String
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized.
 * @kind problem
 * @problem.severity error
 * @id java/formatted-sql-string
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Hibernate

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(MethodParameter p |
      p.getAnUnqualifiedName().regexpMatch("INPUT") and
      this.asParameter() = p
    )
    or
    exists(MethodAccess ma |
      (
        ma.getMethod().hasName("concat") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")
          or
        (ma.getMethod().hasName("append") and 
         (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
          ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer")))
        or
        (ma.getMethod().hasName("format") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
        or
        (ma.getMethod().hasName("join") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String"))
      ) and
      this.asExpr() = ma
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      ma.getMethod().getName().regexpMatch("execute|executeQuery|createQuery|query|addBatch|nativeSQL|create|prepare") and
      this.asExpr() = ma.getArgument(0) and
      not ma.getArgument(0).toString().matches(".*TABLE *$") and
      not ma.getArgument(0).toString().matches(".*TABLE %s$")
    )
  }
}

class CriteriaBuilderSanitizer extends DataFlow::BarrierNode {
  CriteriaBuilderSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence.criteria", "CriteriaBuilder") and
      this.asExpr() = ma
    )
  }
}

class FormattedSqlStringConfig extends TaintTracking::Configuration {
  FormattedSqlStringConfig() { this = "FormattedSqlStringConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlFormatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof CriteriaBuilderSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
       ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer")) and
      ma.getMethod().hasName("append") and
      pred.asExpr() = ma.getArgument(0) and
      succ.asExpr() = ma
    )
  }
}

from FormattedSqlStringConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements instead."