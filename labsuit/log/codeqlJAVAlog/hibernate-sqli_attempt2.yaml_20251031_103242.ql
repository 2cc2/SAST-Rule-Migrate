/**
 * @name Hibernate SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables
 *              in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id java/hibernate-sqli
 * @tags security
 *       external/cwe/cwe-089
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
    exists(AssignmentExpr assign |
      assign.getDest().getType().hasName("String") and
      exists(assign.getSource() |
        this.asExpr() = assign.getSource()
      ) and
      assign.getSource().toString().matches("%.*\\+.*%")
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
      (ma.getMethod().hasName("createQuery") or ma.getMethod().hasName("createSQLQuery")) and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.hibernate", "Session") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(AssignmentExpr assign |
      assign.getDest().getType().hasName("String") and
      exists(assign.getSource() |
        this.asExpr() = assign.getSource() and
        assign.getSource().toString().matches('".*" *\\+ *".*"')
      )
    )
  }
}

class HibernateSqlInjectionConfig extends TaintTracking::Configuration {
  HibernateSqlInjectionConfig() { this = "HibernateSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or source instanceof StringConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof HibernateSqlRestrictionSink or sink instanceof HibernateSessionSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof StringLiteralSanitizer
  }
}

from HibernateSqlInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential SQL injection vulnerability in Hibernate query due to use of formatted string", 
  source, "User input flows here",
  sink, "SQL query constructed from user input flows here"