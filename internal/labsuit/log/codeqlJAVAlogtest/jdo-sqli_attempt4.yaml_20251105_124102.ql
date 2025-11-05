import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class SQLFormatSource extends DataFlow::Node {
  SQLFormatSource() {
    exists(Method m | 
      m.hasName("format") and 
      m.getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = m.getAReference()
    )
  }
}

class SQLConcatSource extends DataFlow::Node {
  SQLConcatSource() {
    exists(AssignExpr ae |
      ae.getDest().toString().matches("%SQL%") and
      ae.getSource().toString().matches("%+%") and
      this.asExpr() = ae
    )
  }
}

class SQLParamSource extends DataFlow::ParameterNode {
  SQLParamSource() {
    this.getParameter().getName().matches("%SQL%")
  }
}

class JDOQuerySink extends DataFlow::Node {
  JDOQuerySink() {
    exists(Method m |
      (m.hasName("setFilter") or m.hasName("setGrouping")) and
      m.getDeclaringType().hasQualifiedName("javax.jdo", "Query") and
      this.asExpr() = m.getAnInvocation().getArgument(0)
    ) or
    exists(Method m |
      m.hasName("newQuery") and
      m.getDeclaringType().hasQualifiedName("javax.jdo", "PersistenceManager") and
      this.asExpr() = m.getAnInvocation().getArgument(1)
    )
  }
}

class SafeConcatSanitizer extends DataFlow::Node {
  SafeConcatSanitizer() {
    exists(AssignExpr ae |
      exists(StringLiteral sl | ae.getSource() = sl) and
      this.asExpr() = ae
    )
  }
}

class SafeParamSanitizer extends DataFlow::ParameterNode {
  SafeParamSanitizer() {
    exists(StringLiteral sl |
      exists(DataFlow::Node node | node.asExpr() = sl and node = this.getAnAccess())
    )
  }
}

class JdoSqlInjectionConfig extends TaintTracking::Configuration {
  JdoSqlInjectionConfig() { this = "JdoSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SQLFormatSource or
    source instanceof SQLConcatSource or
    source instanceof SQLParamSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof JDOQuerySink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SafeConcatSanitizer or
    sanitizer instanceof SafeParamSanitizer
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where any(JdoSqlInjectionConfig conf).hasFlowPath(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL " +
  "injection if variables in the SQL statement are not properly sanitized. Use prepared " +
  "statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement " +
  "using 'connection.prepareStatement'.", source, "Potential SQL injection"