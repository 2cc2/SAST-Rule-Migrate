/**
 * @name Hibernate SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection 
 * if variables in the SQL statement are not properly sanitized.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 *       java
 *       hibernate
 */

import java
import semmle.code.java.Strings
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Hibernate

class SqlFormatSource extends MethodAccess {
  SqlFormatSource() {
    this.getMethod().hasName("format") and
    this.getMethod().getDeclaringType().getName() = "String"
  }
}

class StringConcatSource extends Expr {
  StringConcatSource() {
    exists(Assignment a |
      a.getTarget() instanceof LocalVariableAccess and
      a.getExpr().toString().matches("%String%.*\\+.*")
    )
  }
}

class SqlRestrictionSink extends MethodAccess {
  SqlRestrictionSink() {
    this.getMethod().getName() = "sqlRestriction" and
    this.getMethod().getDeclaringType().getName() = "Restrictions" and
    this.getArgument(0) instanceof Expr
  }
}

class SessionMethodSink extends MethodAccess {
  SessionMethodSink() {
    this.getMethod().getName().matches("createQuery|createSQLQuery") and
    this.getMethod().getDeclaringType().getName() = "Session" and
    this.getArgument(0) instanceof Expr
  }
}

class LiteralConcatSanitizer extends Expr {
  LiteralConcatSanitizer() {
    exists(Assignment a |
      a.getTarget() instanceof LocalVariableAccess and
      a.getExpr().toString().matches("%String%.*=\\s*\".*\"\\s*\\+\\s*\".*\"")
    )
  }
}

class HibernateSqlInjectionConfig extends TaintTracking::Configuration {
  HibernateSqlInjectionConfig() { this = "HibernateSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof SqlFormatSource or
    source.asExpr() instanceof StringConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof SqlRestrictionSink or
    sink.asExpr() instanceof SessionMethodSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() instanceof LiteralConcatSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Parameter p, Argument a |
      pred = a.getNode() and
      succ = p.getNode()
    )
  }
}

from HibernateSqlInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlowPath(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection " +
  "if variables in the SQL statement are not properly sanitized. Use prepared statements " +
  "(java.sql.PreparedStatement) instead."