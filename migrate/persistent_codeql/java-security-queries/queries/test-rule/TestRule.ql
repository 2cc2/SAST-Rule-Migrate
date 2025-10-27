/**
 * @name JDBC SQL Formatted String Injection
 * @description Detects possible JDBC injection when using string formatting/concatenation
 *              instead of parameterized queries with JdbcTemplate methods.
 * @kind path-problem
 * @problem.severity warning
 * @id java/jdbc-sql-formatted-string
 * @tags security
 *       external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.spring.JdbcTemplate

class StringFormatSource extends DataFlow::Node {
  StringFormatSource() {
    exists(Method m, Call ma |
      m.hasName("format") and
      m.getDeclaringType().hasQualifiedName("java.lang", "String") and
      ma.getCallee() = m and
      this.asExpr() = ma
    )
  }
}

class StringConcatSource extends DataFlow::Node {
  StringConcatSource() {
    exists(AddExpr e |
      e.getLeftOperand().getType() instanceof TypeString and
      e.getRightOperand().getType() instanceof TypeString and
      this.asExpr() = e
    )
  }
}

class JdbcSink extends DataFlow::Node {
  JdbcSink() {
    exists(Method m, Call ma |
      m.hasName(["queryForObject", "update", "execute", "insert"]) and
      m.getDeclaringType().getASupertype*().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
      ma.getCallee() = m and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class JdbcTaintConfig extends TaintTracking::Configuration {
  JdbcTaintConfig() { this = "JdbcTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or source instanceof StringConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof JdbcSink
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, JdbcTaintConfig config
where config.hasFlowPath(source, sink)
select sink, "Possible JDBC injection detected. Use parameterized queries instead of string concatenation/formatting.",
  source, "This is the source of the formatted/concatenated string",
  sink, "This is the JDBC query sink"