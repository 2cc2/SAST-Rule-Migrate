/**
 * @id tainted-sql-string
 * @kind path-problem
 * @severity error
 * @name Tainted SQL string
 * @description User data flows into this manually-constructed SQL string. User data can be safely
 *              inserted into SQL strings using prepared statements or an object-relational mapper (ORM).
 *              Manually-constructed SQL strings is a possible indicator of SQL injection, which could
 *              let an attacker steal or manipulate data from the database. Instead, use prepared statements
 *              (`connection.PreparedStatement`) or a safe library.
 * @tags security
 * @tags spring
 * @problem.decimal CWE-89
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class UserInputParameter extends DataFlow::Node {
  UserInputParameter() {
    exists(MethodParameter p |
      p = this.asParameter() and
      not p.getType().toString().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)") and
      exists(Annotation a |
        a = p.getAnAnnotation() and
        a.getType().getName().matches("(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue)")
      )
    )
  }
}

class StringConcatenation extends DataFlow::Node {
  StringConcatenation() {
    exists(Method m, MethodAccess ma |
      ma = this.asExpr() and
      (
        m.getName().matches("%\\.concat%") or
        m.getName().matches("%\\.append%") or
        m.getName().matches("String\\.format%")
      ) and
      m = ma.getMethod() and
      ma.getQualifier().getType().toString() = "java.lang.String" and
      exists(Expr arg |
        arg = ma.getArgument(0) and
        arg.toString().matches("(?i)(select|delete|insert|create|update|alter|drop)\\b")
      ) and
      not m.getName().matches("%(System\\.out\\.println|LOG\\.(info|warn|warning|debug|debugging|error)|Exception)%")
    )
  }
}

class TaintedSQLConfig extends TaintTracking::Configuration {
  TaintedSQLConfig() { this = "TaintedSQLConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UserInputParameter
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof StringConcatenation
  }
}

from TaintedSQLConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "User data flows into this manually-constructed SQL string. This could lead to SQL injection vulnerabilities ($@).",
  source.getNode(), "User input"