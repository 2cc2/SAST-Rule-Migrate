/**
 * @name JPA SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if 
 *              variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @id java/jpa-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringUtil

class SqlConcatSource extends DataFlow::Expr {
  SqlConcatSource() {
    // Match String.format calls
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this = ma
    )
    or
    // Match string concatenation
    exists(BinaryExpr be |
      be.getOp() = BinaryOperator.PLUS and
      be.getLeftOperand().getType() instanceof StringType and
      be.getRightOperand().getType() instanceof StringType and
      this = be
    )
  }
}

class MethodParamSqlSource extends DataFlow::Parameter {
  MethodParamSqlSource() {
    this.getType() instanceof StringType and
    this.getName().matches(".*(?i)sql.*")
  }
}

class SqlExecutionSink extends DataFlow::Expr {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("createQuery|createNativeQuery") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence", "EntityManager") and
      this = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Expr {
  StringLiteralSanitizer() {
    exists(StringLiteral sl |
      sl.getValue().matches("^\"[^\"]*\"\\s*\\+\\s*\"[^\"]*\"$") and
      this = sl
    )
  }
}

class JpaSqlInjectionConfig extends TaintTracking::Configuration {
  JpaSqlInjectionConfig() { this = "JpaSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof SqlConcatSource or
    source.asParameter() instanceof MethodParamSqlSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof SqlExecutionSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() instanceof StringLiteralSanitizer
  }
}

from JpaSqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if" +
  " variables in the SQL statement are not properly sanitized. Use prepared statements" +
  " (java.sql.PreparedStatement) instead."