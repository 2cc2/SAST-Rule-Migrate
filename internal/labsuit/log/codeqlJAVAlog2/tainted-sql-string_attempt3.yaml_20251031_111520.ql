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
import java
import semmle.code.java.frameworks.spring.SpringController
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat

predicate isUserInputSource(Parameter param) {
  not param.getType().toString().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)$")
  and
  exists(Annotation ann | 
    ann.getType().getName().matches("RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue") |
    param.getAnAnnotation() = ann
  )
}

class SqlConcatSink extends TaintTracking::Sink {
  SqlConcatSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getName().matches("%concat%") or
        ma.getMethod().getName().matches("%append%") or
        exists(StringFormat::FormatLiteral fmt | ma.getMethod().getName() = "format" |
          fmt.getAnArgument() = ma.getArgument(0)
        )
      )
      and
      ma.getReceiver().getType().getName() = "String"
      and
      ma.getArgument(0).toString().regexpMatch("(?i)(select|delete|insert|create|update|alter|drop)\\b")
      and
      not ma.getMethod().getName().matches("System\\.out\\.println|LOG\\.(info|warn|warning|debug|debugging|error)|Exception")
      and
      this.asExpr() = ma
    )
  }
}

class TaintedSqlConfig extends TaintTracking::Configuration {
  TaintedSqlConfig() { this = "TaintedSqlConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p | isUserInputSource(p) | source.asParameter() = p)
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlConcatSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Propagate taint through argument to parameter
    exists(DataFlow::ParameterNode param, DataFlow::ExprNode arg |
      param.asParameter() = param and
      arg.asExpr() = arg and
      param.getCallable().getAParameter() = param and
      arg.asExpr() = param.getCallable().getAParameter().getAnAccess() and
      node1.asExpr() = arg and
      node2.asParameter() = param
    )
  }
}

from TaintedSqlConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, 
  "User data flows into this manually-constructed SQL string. " +
  "User data can be safely inserted into SQL strings using prepared statements " +
  "or an object-relational mapper (ORM).", 
  source, sink, "Potential SQL injection vulnerability"