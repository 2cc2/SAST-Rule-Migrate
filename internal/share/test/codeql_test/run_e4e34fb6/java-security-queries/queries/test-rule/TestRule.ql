/**
 * @id turbine-sqli
 * @severity WARNING
 * @message Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.MethodAccess
import semmle.code.java.dataflow.DataFlow::PathNode
import semmle.code.java.StringUtil

class TurbineSqlInjection extends TaintTracking::Configuration {
  TurbineSqlInjection() { this = "TurbineSqlInjection" }

  override predicate isSource(DataFlow::Node source) {
    // Source 1: String.format() calls or string concatenation
    exists(MethodAccess ma |
      (ma.getMethod().hasName("format") and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")) or
      ma.getArgument(0).getType() instanceof TypeString and exists(ma.getArgument(0).toString()) 
    |
      source.asExpr() = ma
    )
    or
    // Source 2: Parameter named $SQL
    exists(Parameter p | p.getName() = "$SQL" | source.asParameter() = p)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().hasName("BasePeer") or
       ma.getMethod().getDeclaringType().hasName("GroupPeer")) and
      ma.getMethod().hasName("executeQuery")
    |
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    // Literal strings are considered sanitized
    exists(StringLiteral sl | sanitizer.asExpr() = sl)
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Propagation through argument to parameter
    exists(MethodAccess ma, Parameter p |
      exists(ma.getAnArgument() | _ = node1.asExpr()) and
      p = ma.getMethod().getAParameter() and
      node2.asParameter() = p
    )
  }
}

from TurbineSqlInjection config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SQL injection vulnerability due to unparameterized SQL query"