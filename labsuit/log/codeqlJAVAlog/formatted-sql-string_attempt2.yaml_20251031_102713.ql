/**
 * @name Formatted SQL string
 * @description Detected a formatted string in a SQL statement.
 * @kind problem
 * @id java/formatted-sql-string
 * @severity ERROR
 * @tags security
 *       cwe
 *       sql-injection
 * @precision high
 */
import java
import DataFlow::PathGraph
import TaintTracking::Configuration

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(Parameter p | 
      p.getType().hasName("String") and
      (regexpMatch("INPUT", p.getName()) or
       this.asExpr() = any(Method m |
         m.hasName("concat") and m.getDeclaringType().hasQualifiedName("java.lang", "String") and
         this.asExpr() = m.getACall().getArgument(0)
       ) or
       this.asExpr() = any(Method m |
         (m.hasName("append") and 
          (m.getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
           m.getDeclaringType().hasQualifiedName("java.lang", "StringBuffer"))) and
         this.asExpr() = m.getACall().getArgument(0)
       ) or
       this.asExpr() = any(Method m |
         (m.hasName("format") or m.hasName("join")) and
         m.getDeclaringType().hasQualifiedName("java.lang", "String") and
         this.asExpr() = m.getACall().getArgument(0)
       ))
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(Method m |
      m.getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      regexpMatch("execute|executeQuery|createQuery|query|addBatch|nativeSQL|create|prepare", m.getName()) and
      this.asExpr() = m.getACall().getArgument(0) and
      not regexpMatch(".*TABLE *$", this.asExpr().toString()) and
      not regexpMatch(".*TABLE %s$", this.asExpr().toString())
    )
  }
}

class CriteriaBuilderSanitizer extends DataFlow::Node {
  CriteriaBuilderSanitizer() {
    exists(Method m |
      m.getDeclaringType().hasQualifiedName("javax.persistence.criteria", "CriteriaBuilder") and
      this.asExpr() = m.getACall()
    )
  }
}

class SqlStringFormatConfig extends TaintTracking::Configuration {
  SqlStringFormatConfig() { this = "SqlStringFormatConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof SqlFormatSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlExecutionSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof CriteriaBuilderSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Method m |
      (m.getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
       m.getDeclaringType().hasQualifiedName("java.lang", "StringBuffer")) and
      m.getName() = "append" and
      pred.asExpr() = m.getACall().getArgument(0) and
      succ.asExpr() = m.getACall()
    )
  }
}

from SqlStringFormatConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection if " +
  "variables in the SQL statement are not properly sanitized. Use prepared statements " +
  "(java.sql.PreparedStatement) instead."