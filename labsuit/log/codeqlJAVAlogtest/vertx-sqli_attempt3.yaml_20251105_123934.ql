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
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class StringFormatSource extends DataFlow::Node {
  StringFormatSource() {
    exists(MethodAccess ma | 
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
  }
}

class SqlConcatSource extends DataFlow::Node {
  SqlConcatSource() {
    exists(AssignExpr assign |
      assign.getChild(1).toString().regexpMatch("String \\$SQL = \\$X \\+ \\$Y") and
      this.asExpr() = assign.getChild(1)
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().hasQualifiedName("io.vertx.sqlclient", "SqlClient", ["query", "preparedQuery", "prepare"]) or
        ma.getMethod().hasQualifiedName("io.vertx.sqlclient", "SqlConnection", ["query", "preparedQuery", "prepare"])
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class LiteralSanitizer extends DataFlow::Node {
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

from VertxSQLIConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized."