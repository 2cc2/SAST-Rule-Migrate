/**
 * @id tainted-sql-string
 * @kind path-problem
 * @severity ERROR
 * @message User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL strings is a possible indicator of SQL injection, which could let an attacker steal or manipulate data from the database. Instead, use prepared statements (`connection.PreparedStatement`) or a safe library.
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat

class UserInputSource extends TaintTracking::Source {
  UserInputSource() {
    exists(Method m, Param p |
      this.asParameter() = p and
      not p.getType().toString().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)") and
      exists(Annotation a |
        a.getType().toString().matches("(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue)") and
        p.getAnAnnotation() = a
      )
    )
  }
}

class SqlConcatSink extends TaintTracking::Sink {
  SqlConcatSink() {
    exists(MethodAccess call |
      this.asExpr() = call.getArgument(0) and
      (
        call.getMethod().getName().matches(".*\\.concat") or
        call.getMethod().getName().matches(".*\\.append") or
        call.getMethod().getName().matches("String\\.format")
      ) and
      call.getReceiver().getType().toString() = "java.lang.String" and
      call.getArgument(0).toString().regexpMatches("(?i)(select|delete|insert|create|update|alter|drop)\\b") and
      not call.getMethod().toString().matches("(System\\.out\\.println|LOG\\.(info|warn|warning|debug|debugging|error)|Exception)")
    )
  }
}

class MyTaintTrackingConfig extends TaintTracking::Configuration {
  MyTaintTrackingConfig() { this = "TaintedSqlString" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UserInputSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlConcatSink
  }
}

from MyTaintTrackingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "User data flows into this manually-constructed SQL string, which could lead to SQL injection."