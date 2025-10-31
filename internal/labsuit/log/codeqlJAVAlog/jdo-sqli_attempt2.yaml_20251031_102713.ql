/**
 * @name JDOSQLi
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables
 *              in the SQL statement are not properly sanitized. Use a prepared statements
 *              (java.sql.PreparedStatement) instead.
 * @kind path-problem
 * @problem.severity warning
 * @id java/jdo-sqli
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.jdo.JDO

class SQLFormatSource extends TaintTracking::Source {
  SQLFormatSource() {
    exists(MethodCall call |
      call.getMethod().getName() = "format" and
      call.getMethod().getDeclaringType().getName() = "String" and
      this.asExpr() = call
    )
  }
}

class SQLConcatSource extends TaintTracking::Source {
  SQLConcatSource() {
    exists(AssignExpr assign |
      assign.getRight().toString().matches("%SQL = %X + %Y") and
      this.asExpr() = assign
    )
  }
}

class SQLParamSource extends TaintTracking::Source {
  SQLParamSource() {
    exists(Parameter param |
      param.getName().matches("%SQL%") and
      this.asParameter() = param
    )
  }
}

class JDOQuerySink extends TaintTracking::Sink {
  JDOQuerySink() {
    exists(MethodCall call |
      (
        call.getMethod().getName() = "setFilter" and
        call.getMethod().getDeclaringType().getName() = "Query" and
        call.getMethod().getDeclaringType().getAPackage().getName() = "javax.jdo"
        or
        call.getMethod().getName() = "setGrouping" and
        call.getMethod().getDeclaringType().getName() = "Query" and
        call.getMethod().getDeclaringType().getAPackage().getName() = "javax.jdo"
        or
        call.getMethod().getName() = "newQuery" and
        call.getMethod().getDeclaringType().getName() = "PersistenceManager" and
        call.getMethod().getDeclaringType().getAPackage().getName() = "javax.jdo"
      ) and
      this.asExpr() = call.getArgument(0)
    )
  }
}

class SafeConcatSanitizer extends TaintTracking::Sanitizer {
  SafeConcatSanitizer() {
    exists(AssignExpr assign |
      assign.getRight().toString().matches("%SQL = \"...\" + \"...\"") and
      this.asExpr() = assign
    )
  }
}

class SafeParamSanitizer extends TaintTracking::Sanitizer {
  SafeParamSanitizer() {
    exists(Parameter param |
      param.getAnAccess().toString() = "\"...\"" and
      this.asParameter() = param
    )
  }
}

class JDOConfig extends TaintTracking::Configuration {
  JDOConfig() { this = "JDO SQL Injection" }

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

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    pred.asParameter().getAnAccess() = succ.asExpr()
  }
}

from JDOConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected a formatted string in a SQL statement. $@",
  source.getNode(), "User input"