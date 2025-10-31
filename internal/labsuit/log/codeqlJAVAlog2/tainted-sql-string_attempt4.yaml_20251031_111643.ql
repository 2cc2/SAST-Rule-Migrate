/**
 * @name Tainted SQL String
 * @description User data flows into this manually-constructed SQL string. 
 * User data can be safely inserted into SQL strings using prepared statements 
 * or an object-relational mapper (ORM). Manually-constructed SQL strings is 
 * a possible indicator of SQL injection, which could let an attacker steal 
 * or manipulate data from the database. 
 * @kind path-problem
 * @problem.severity error 
 * @security-severity 8.8
 * @precision high
 * @id java/tainted-sql-string
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */

/**********************************************************************
 * MODULE IMPORTS
 **********************************************************************/
import codeql.java.AST
import codeql.java.Metrics
import codeql.java.dataflow.DataFlow
import codeql.java.dataflow.TaintTracking

/**********************************************************************
 * SOURCE DEFINITION
 **********************************************************************/
predicate isUserInputSource(DataFlow::Node node) {
  exists(Parameter p |
    node.asParameter() = p and
    not p.getType().toString().regexpMatch("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)$") and
    exists(Annotation ann | 
      ann.getTypeName().regexpMatch("RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue") and
      p.getAnAnnotation() = ann
    )
  )
}

/**********************************************************************
 * SINK DEFINITION 
 **********************************************************************/
class SqlConcatSink extends DataFlow::Node {
  SqlConcatSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getName().regexpMatch(".*concat.*") or
        ma.getMethod().getName().regexpMatch(".*append.*") or
        ma.getMethod().getName() = "format"
      ) and
      ma.getQualifier().getType().getName() = "String" and
      ma.getArgument(0).toString().regexpMatch("(?i)(select|delete|insert|create|update|alter|drop)\\b") and
      not ma.getMethod().getName().regexpMatch("System\\.out\\.println|LOG\\.(info|warn|warning|debug|debugging|error)|Exception") and
      this.asExpr() = ma
    )
  }
}

/**********************************************************************
 * DATAFLOW CONFIGURATION
 **********************************************************************/
class TaintedSqlConfig extends TaintTracking::Configuration {
  TaintedSqlConfig() { this = "TaintedSqlConfig" }

  override predicate isSource(DataFlow::Node source) {
    isUserInputSource(source)
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlConcatSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(DataFlow::CallNode call, DataFlow::ParameterNode param |
      call.getArgument(0) = node1.asExpr() and
      param = node2.asParameter() and
      param.getCallable() = call.getCallee()
    )
  }
}

/**********************************************************************
 * MAIN QUERY
 **********************************************************************/
from TaintedSqlConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, 
  "User data flows into this manually-constructed SQL string. " +
  "User data can be safely inserted into SQL strings using prepared statements " +
  "or an object-relational mapper (ORM).", 
  source, sink, "Potential SQL injection vulnerability"