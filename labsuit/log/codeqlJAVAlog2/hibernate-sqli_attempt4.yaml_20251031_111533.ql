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

class SqlFormatSource extends DataFlow::CallNode {
  SqlFormatSource() {
    exists(Method m |
      m.hasName("format") and
      m.getDeclaringType().getName() = "String" and
      this.getTarget() = m
    )
  }
}

class StringConcatSource extends DataFlow::Node {
  StringConcatSource() {
    exists(AssignExpr a |
      a.getDest() instanceof LocalVariableExpr and
      a.getSrc().toString().matches("%String%.*\\+.*")
    ) or
    this.getNode() instanceof AssignExpr and
    this.getNode().getSrc().toString().matches("%String%.*\\+.*")
  }
}

class SqlRestrictionSink extends DataFlow::CallNode {
  SqlRestrictionSink() {
    exists(Method m |
      m.hasName("sqlRestriction") and
      m.getDeclaringType().getName() = "Restrictions" and
      this.getTarget() = m and
      this.getArgument(0) instanceof Expr
    )
  }
}

class SessionMethodSink extends DataFlow::CallNode {
  SessionMethodSink() {
    exists(Method m |
      m.getName().matches("createQuery|createSQLQuery") and
      m.getDeclaringType().getName() = "Session" and
      this.getTarget() = m and
      this.getArgument(0) instanceof Expr
    )
  }
}

class LiteralConcatSanitizer extends DataFlow::Node {
  LiteralConcatSanitizer() {
    exists(AssignExpr a |
      a.getDest() instanceof LocalVariableExpr and
      a.getSrc().toString().matches("%String%.*=\\s*\".*\"\\s*\\+\\s*\".*\"")
    ) or
    this.getNode() instanceof AssignExpr and
    this.getNode().getSrc().toString().matches("%String%.*=\\s*\".*\"\\s*\\+\\s*\".*\"")
  }
}

class HibernateSqlInjectionConfig extends TaintTracking::Configuration {
  HibernateSqlInjectionConfig() { this = "HibernateSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlFormatSource or
    source instanceof StringConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlRestrictionSink or
    sink instanceof SessionMethodSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof LiteralConcatSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma, Parameter p |
      pred.asExpr() = ma.getAnArgument() and
      succ.asParameter() = p
    )
  }
}

from HibernateSqlInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlowPath(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection " +
  "if variables in the SQL statement are not properly sanitized. Use prepared statements " +
  "(java.sql.PreparedStatement) instead."