import java

import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.jdo.JDO
import DataFlow::PathGraph

class SQLFormatSource extends DataFlow::Expr {
  SQLFormatSource() {
    exists(Method m | 
      m.hasName("format") and 
      m.getDeclaringType().hasQualifiedName("java.lang", "String") and
      this = m.getACall()
    )
  }
}

class SQLConcatSource extends DataFlow::Expr {
  SQLConcatSource() {
    exists(AssignExpr ae |
      ae.getDest().toString().matches("%SQL%") and
      ae.getSourceExpr().toString().matches("%+%") and
      this = ae
    )
  }
}

class SQLParamSource extends DataFlow::Parameter {
  SQLParamSource() {
    this.toString().matches("%SQL%")
  }
}

class JDOQuerySink extends DataFlow::Expr {
  JDOQuerySink() {
    exists(Method m |
      (m.hasName("setFilter") or m.hasName("setGrouping")) and
      m.getDeclaringType().hasQualifiedName("javax.jdo", "Query") and
      this = m.getCall(0)
    ) or
    exists(Method m |
      m.hasName("newQuery") and
      m.getDeclaringType().hasQualifiedName("javax.jdo", "PersistenceManager") and
      this = m.getCall(1)
    )
  }
}

class SafeConcatSanitizer extends DataFlow::Expr {
  SafeConcatSanitizer() {
    exists(AssignExpr ae |
      ae.getSourceExpr().(StringLiteral).exists() and
      this = ae
    )
  }
}

class SafeParamSanitizer extends DataFlow::Parameter {
  SafeParamSanitizer() {
    exists(StringLiteral sl |
      this.getAnAccess().getSource() = sl
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

from JdoSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL " +
  "injection if variables in the SQL statement are not properly sanitized. Use prepared " +
  "statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement " +
  "using 'connection.prepareStatement'.", source, "Potential SQL injection"