/**
 * @name JDOSQL Injection
 * @id jdo-sqli
 * @kind problem
 * @severity Warning
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection
 *              if variables in the SQL statement are not properly sanitized. Use a prepared statements
 *              (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using
 *              'connection.prepareStatement'.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.frameworks.DataFlow

class SqlSource extends DataFlow::Node {
  SqlSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    ) or
    exists(AssignExpr assign |
      assign.getRValue().getType().toString() = "String" and
      assign.getRValue().toString().matches("%SQL = %X + %Y") and
      this.asExpr() = assign.getRValue()
    ) or
    exists(Parameter p |
      p.getName().matches("%SQL%") and
      this.asParameter() = p
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getName() = "setFilter" and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "Query") and
        this.asExpr() = ma.getArgument(0)
      ) or
      (
        ma.getMethod().getName() = "setGrouping" and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "Query") and
        this.asExpr() = ma.getArgument(0)
      ) or
      (
        ma.getMethod().getName() = "newQuery" and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "PersistenceManager") and
        this.asExpr() = ma.getArgument(1)
      )
    )
  }
}

class SafeAssignment extends DataFlow::Node {
  SafeAssignment() {
    exists(AssignExpr assign |
      assign.getRValue().getType().toString() = "String" and
      assign.getRValue().toString().matches("\"...\" + \"...\"") and
      this.asExpr() = assign.getRValue()
    )
  }
}

class SafeParameter extends DataFlow::Node {
  SafeParameter() {
    exists(Parameter p |
      p.getInitializer().toString().matches("\"...\"") and
      this.asParameter() = p
    )
  }
}

class SqlTaintTrackingConfiguration extends TaintTracking::Configuration {
  SqlTaintTrackingConfiguration() { this = "SqlTaintTrackingConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof SqlSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof SafeAssignment or node instanceof SafeParameter
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess mc |
      pred.asExpr() = mc.getArgument(_) and
      succ.asParameter() = mc.getMethod().getAParameter()
    )
  }
}

from SqlTaintTrackingConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SQL injection vulnerability due to using formatted strings in JDO query"