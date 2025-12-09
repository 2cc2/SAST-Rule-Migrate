/**
 * @name Hibernate SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized.
 * @kind problem
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

class StringFormatSource extends DataFlow::Node {
  StringFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }
}

class StringConcatSource extends DataFlow::Node {
  StringConcatSource() {
    exists(Assignment assign |
      assign.getRight().toString().matches("String.*=.*\\+.*") and
      this.asExpr() = assign.getRight()
    )
  }
}

class HibernateSqlRestrictionSink extends DataFlow::Node {
  HibernateSqlRestrictionSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("sqlRestriction") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.hibernate.criterion", "Restrictions") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class HibernateSessionSink extends DataFlow::Node {
  HibernateSessionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("createQuery|createSQLQuery") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.hibernate", "Session") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(Assignment assign |
      assign.getRight().toString().matches("String.*=.*\".*\" *\\+ *\".*\"") and
      this.asExpr() = assign.getRight()
    )
  }
}

class HibernateSqlInjectionConfig extends TaintTracking::Configuration {
  HibernateSqlInjectionConfig() { this = "HibernateSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or
    source instanceof StringConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof HibernateSqlRestrictionSink or
    sink instanceof HibernateSessionSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof StringLiteralSanitizer
  }
}

from HibernateSqlInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead."