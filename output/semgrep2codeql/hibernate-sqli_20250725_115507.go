/**
 * @name Hibernate SQL Injection
 * @description Detects potential SQL injection vulnerabilities in Hibernate when using string concatenation
 *              or String.format() to construct SQL queries instead of prepared statements.
 * @kind path-problem
 * @problem.severity warning
 * @id java/hibernate-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import semmle.code.java.frameworks.Hibernate

class HibernateRestrictions extends RefType {
  HibernateRestrictions() {
    this.hasQualifiedName("org.hibernate.criterion", "Restrictions")
  }
}

class SqlRestrictionMethod extends Method {
  SqlRestrictionMethod() {
    this.getDeclaringType() instanceof HibernateRestrictions and
    this.getName() = "sqlRestriction"
  }
}

class HibernateSession extends RefType {
  HibernateSession() {
    this.hasQualifiedName("org.hibernate", "Session")
  }
}

class DangerousSessionMethod extends Method {
  DangerousSessionMethod() {
    this.getDeclaringType() instanceof HibernateSession and
    (this.getName() = "createQuery" or this.getName() = "createSQLQuery")
  }
}

class StringConcatenationSource extends DataFlow::Node {
  StringConcatenationSource() {
    exists(Expr expr |
      (expr instanceof AddExpr or 
       exists(MethodCall mc | 
         mc.getMethod().hasName("format") and
         mc.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
         expr = mc
       )
      ) and
      this.asExpr() = expr
    )
  }
}

class SqlRestrictionSink extends DataFlow::Node {
  SqlRestrictionSink() {
    exists(Call ma |
      ma.getCallee() instanceof SqlRestrictionMethod and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class SessionMethodSink extends DataFlow::Node {
  SessionMethodSink() {
    exists(Call ma |
      ma.getCallee() instanceof DangerousSessionMethod and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class HibernateSqlInjectionConfig extends TaintTracking::Configuration {
  HibernateSqlInjectionConfig() { this = "HibernateSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringConcatenationSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlRestrictionSink or sink instanceof SessionMethodSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Literal lit | sanitizer.asExpr() = lit)
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, HibernateSqlInjectionConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential SQL injection in Hibernate: Detected a formatted string in a SQL statement. " +
  "This could lead to SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use prepared statements (java.sql.PreparedStatement) instead."