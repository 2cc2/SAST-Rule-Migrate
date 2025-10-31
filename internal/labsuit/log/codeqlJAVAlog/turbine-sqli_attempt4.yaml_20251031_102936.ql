/** 
 * @name turbine-sqli
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection 
 * if variables in the SQL statement are not properly sanitized. Use a prepared statements 
 * (java.sql.PreparedStatement) instead.
 * @id turbine-sqli
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.MethodAccess
import semmle.code.java.Parameter
import semmle.code.java.Literal

class SqlConcatSource extends MethodAccess {
  SqlConcatSource() {
    getMethod().hasName("format") and
    getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")
    or
    exists(MethodAccess ma | ma.getMethod().getName().matches("%+%"))
  }
}

class SqlParamSource extends Parameter {
  SqlParamSource() {
    getName() = "$SQL"
  }
}

class SqlExecutionSink extends MethodAccess {
  SqlExecutionSink() {
    getMethod().getName() = "executeQuery" and
    (
      getMethod().getDeclaringType().hasQualifiedName("", "BasePeer") or
      getMethod().getDeclaringType().hasQualifiedName("", "GroupPeer")
    )
  }
}

class SqlLiteralSanitizer extends Literal {
  SqlLiteralSanitizer() {
    getType().hasName("java.lang.String") and
    getValue().matches("^\".+\"$")
  }
}

class TurbineSqliConfig extends TaintTracking::Configuration {
  TurbineSqliConfig() { this = "TurbineSqliConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof SqlConcatSource or
    source.asParameter() instanceof SqlParamSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof SqlExecutionSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() instanceof SqlLiteralSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    any(MethodAccess call, int arg |
      pred.asExpr() = call.getArgument(arg) and
      succ.asExpr() = call
    )
  }
}

from TurbineSqliConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SQL injection vulnerability due to using concatenated strings in SQL query"