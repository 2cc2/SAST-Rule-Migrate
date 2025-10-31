/**
 * @id formatted-sql-string
 * @severity ERROR
 * @precision high
 * @kind path-problem
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import DataFlow
import TaintTracking

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(Parameter p |
      p = this.asParameter() and
      regexpMatches(p.getName(), "$INPUT")
    )
    or
    exists(Method m |
      this.asExpr() = m.getACall() and
      (
        m.getQualifiedName() = "java.lang.String.concat" or
        m.getQualifiedName() = "java.lang.StringBuilder.append" or
        m.getQualifiedName() = "java.lang.StringBuffer.append" or
        m.getQualifiedName() = "java.lang.String.format" or
        m.getQualifiedName() = "java.lang.String.join"
      )
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(Method m, DataFlow::Node arg |
      this.asExpr() = m.getACall() and
      m.getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      regexpMatches(m.getName(), "execute|executeQuery|createQuery|query|addBatch|nativeSQL|create|prepare") and
      arg = this.asExpr().getArgument(0) and
      not regexpMatches(arg.getExpr().toString(), ".*TABLE *$") and
      not regexpMatches(arg.getExpr().toString(), ".*TABLE %s$")
    )
  }
}

class CriteriaBuilderSanitizer extends DataFlow::Node {
  CriteriaBuilderSanitizer() {
    exists(Method m |
      this.asExpr() = m.getACall() and
      m.getDeclaringType().hasQualifiedName("javax.persistence.criteria", "CriteriaBuilder")
    )
  }
}

class StringConcatTaintStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node src, DataFlow::Node sink) {
    exists(Method m, DataFlow::CallNode call |
      call = m.getACall() and
      (
        m.getDeclaringType().hasQualifiedName("java.lang", "StringBuffer") and
        m.getName() = "append"
        or
        m.getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
        m.getName() = "append"
      ) and
      src.asExpr() = call.getArgument(0) and
      sink.asExpr() = call
    )
  }
}

class SqlStringFormatConfig extends TaintTracking::Configuration {
  SqlStringFormatConfig() { this = "SQL string formatting" }

  override predicate isSource(DataFlow::Node source) { source instanceof SqlFormatSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlExecutionSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof CriteriaBuilderSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node src, DataFlow::Node sink) {
    taintStep instanceof StringConcatTaintStep and
    taintStep.step(src, sink)
  }
}

from SqlStringFormatConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL " +
  "injection if variables in the SQL statement are not properly sanitized. Use prepared " +
  "statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement " +
  "using 'connection.prepareStatement'."