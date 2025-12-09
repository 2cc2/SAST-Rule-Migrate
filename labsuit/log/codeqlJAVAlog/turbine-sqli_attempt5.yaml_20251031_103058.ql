/**
 * @name Turbine SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead.
 * @id turbine-sqli
 * @kind path-problem
 * @precision medium
 * @severity warning
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 *       turbine
 */

import java
import codeql.java.dataflow.DataFlow
import codeql.java.dataflow.TaintTracking
import codeql.java.Method
import codeql.java.Parameter
import codeql.java.Literal
import DataFlow::PathGraph

class SqlConcatSource extends DataFlow::Node {
  SqlConcatSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("java.lang", "String", "format") and
      ma = this.asExpr()
    ) or
    exists(Expr e |
      this.asExpr() = e and
      e instanceof AddExpr and
      e.toString().matches("%+%")
    )
  }
}

class SqlParamSource extends DataFlow::Node {
  SqlParamSource() {
    exists(Parameter p |
      p.getName() = "$SQL" and
      this.asParameter() = p
    )
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().hasQualifiedName("", "BasePeer") or
       ma.getMethod().getDeclaringType().hasQualifiedName("", "GroupPeer")) and
      ma.getMethod().getName() = "executeQuery" and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class LiteralSanitizer extends DataFlow::Node {
  LiteralSanitizer() {
    exists(Literal l |
      l.getType().hasName("java.lang.String") and
      l.getValue().matches("^\".+\"$") and
      this.asExpr() = l
    )
  }
}

class TurbineSqliConfig extends TaintTracking::Configuration {
  TurbineSqliConfig() { this = "TurbineSqliConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlConcatSource or
    source instanceof SqlParamSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof LiteralSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess call, int argIndex |
      call.getArgument(argIndex) = pred.asExpr() and
      succ.asExpr() = call.getMethod().getParameter(argIndex)
    )
  }
}

from TurbineSqliConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead."