/**
 * @name JPA SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection 
 *              if variables in the SQL statement are not properly sanitized. Use prepared statements 
 *              (java.sql.PreparedStatement) instead.
 * @severity Warning
 * @kind path-problem
 * @id java/jpa-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat

class SqlConcatSource extends DataFlow::ExprNode {
  SqlConcatSource() {
    exists(MethodAccess ma | 
      ma.getMethod().getName() = "format" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
    or
    exists(BinaryExpr be |
      be.getOp() = BinaryOperator.PLUS and
      be.getLeftOperand().getType().hasName("String") and
      be.getRightOperand().getType().hasName("String") and
      this.asExpr() = be
    )
  }
}

class MethodParamSqlSource extends DataFlow::ParameterNode {
  MethodParamSqlSource() {
    exists(Method m | 
      this = m.getAParameter() and
      this.getType().hasName("String") and
      this.getName().matches("%sql%")
    )
  }
}

class SqlExecutionSink extends DataFlow::ExprNode {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence", "EntityManager") and
      (ma.getMethod().getName() = "createQuery" or ma.getMethod().getName() = "createNativeQuery") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::ExprNode {
  StringLiteralSanitizer() {
    exists(StringLiteral sl |
      sl.getValue().matches("^\"[^\"]*\"\\s*\\+\\s*\"[^\"]*\"$") and
      this.asExpr() = sl
    )
  }
}

class JpaSqlInjectionConfig extends TaintTracking::Configuration {
  JpaSqlInjectionConfig() { this = "JpaSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlConcatSource or source instanceof MethodParamSqlSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof StringLiteralSanitizer
  }
}

from JpaSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source.getNode(), 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection. " +
  "Use a prepared statements (java.sql.PreparedStatement) instead."