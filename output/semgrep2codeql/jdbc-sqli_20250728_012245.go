/**
 * @name JDBC SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL
 *              injection if variables in the SQL statement are not properly sanitized.
 *              Use prepared statements (java.sql.PreparedStatement) instead.
 * @kind path-problem
 * @problem.severity warning
 * @id java/jdbc-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class SqlSource extends DataFlow::Node {
  SqlSource() {
    exists(AddExpr sc |
      this.asExpr() = sc
    )
    or
    exists(MethodCall ma |
      ma.getMethod().getName() = "format" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }
}

class StatementSink extends DataFlow::Node {
  StatementSink() {
    exists(MethodCall ma |
      ma.getMethod().getName().matches("executeQuery%") or
      ma.getMethod().getName().matches("execute%") or
      ma.getMethod().getName().matches("executeUpdate%") or
      ma.getMethod().getName().matches("executeLargeUpdate%") or
      ma.getMethod().getName().matches("addBatch%") or
      ma.getMethod().getName() = "nativeSQL" and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class SqlToString extends TaintTracking::Configuration {
  SqlToString() { this = "SqlToString" }

  override predicate isSource(DataFlow::Node source) { source instanceof SqlSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof StatementSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Literal l | sanitizer.asExpr() = l)
  }
}

from SqlToString config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SQL injection from concatenated/format SQL string"