/**
 * @name Vert.x SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @id java/vertx-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01
 *       external/owasp/a03
 *       technology/vertx
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.Expr

class StringFormatSource extends DataFlow::ExprNode {
  StringFormatSource() {
    exists(Method m |
      m.hasName("format") and
      m.getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = any(MethodAccess ma | ma.getMethod() = m).getMethod()
    )
  }
}

class SqlConcatSource extends DataFlow::ExprNode {
  SqlConcatSource() {
    exists(AssignExpr assign |
      assign.getRhs().toString().regexpMatch("String \\$SQL = \\$X \\+ \\$Y") and
      this.asExpr() = assign.getRhs()
    )
  }
}

class SqlSink extends DataFlow::ExprNode {
  SqlSink() {
    exists(Method m |
      (
        m.hasQualifiedName("io.vertx.sqlclient", "SqlClient", ["query", "preparedQuery", "prepare"]) or
        m.hasQualifiedName("io.vertx.sqlclient", "SqlConnection", ["query", "preparedQuery", "prepare"])
      ) and
      this.asExpr() = any(MethodAccess ma | ma.getMethod() = m).getArgument(0)
    )
  }
}

class LiteralSanitizer extends DataFlow::ExprNode {
  LiteralSanitizer() {
    exists(Literal l |
      l.getValue().toString().regexpMatch("^\"...\" \\+ \"...\"$") and
      this.asExpr() = l
    )
  }
}

class VertxSQLIConfig extends TaintTracking::Configuration {
  VertxSQLIConfig() { this = "VertxSQLIConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or
    source instanceof SqlConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof LiteralSanitizer
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, VertxSQLIConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized."