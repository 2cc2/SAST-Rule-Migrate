/**
 * @name SQLAlchemy SQL Injection
 * @description Distinct, Having, Group_by, Order_by, and Filter in SQLAlchemy can cause sql injections if the developer inputs raw SQL into the before-mentioned clauses. This pattern captures relevant cases in which the developer inputs raw SQL into the distinct, having, group_by, order_by or filter clauses and injects user-input into the raw SQL with any function besides 'bindparams'. Use bindParams to securely bind user-input to SQL statements.
 * @kind path-problem
 * @problem.severity warning
 * @id python/sqlalchemy-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    exists(Function f, Parameter p |
      f.getName().regexpMatch("^$FUNC$") and
      p.getName() = "$VAR" and
      p = self.asParameter()
    )
  }
}

class SqlInjectionSink extends DataFlow::Node {
  SqlInjectionSink() {
    exists(MethodCall mc |
      mc.getMethod().getName().regexpMatch("(group_by|order_by|distinct|having|filter)") and
      mc.getQualifier().getType().getName() = "sqlalchemy.orm.query" and
      not mc.getMethod().getName() = "bindparams" and
      mc.getAnArg().getValue().getMethod().getName().regexpMatch("$FORMATFUNC$") and
      self = mc.getAnArg()
    )
  }
}

class BindParamsSanitizer extends DataFlow::BarrierNode {
  BindParamsSanitizer() {
    exists(MethodCall mc |
      mc.getMethod().getName() = "bindparams" and
      this = mc
    )
  }
}

query predicate edges(DataFlow::Node pred, DataFlow::Node succ) {
  DataFlow::parameterNode(pred, succ)
}

from UserInputSource source, SqlInjectionSink sink
where DataFlow::flow(source, sink) and
  not exists(BindParamsSanitizer sanitizer |
    DataFlow::flow(source, sanitizer) and DataFlow::flow(sanitizer, sink)
  )
select sink, "Potential SQL injection vulnerability in SQLAlchemy operation", source,
  "User input reaches potentially unsafe SQL operation $@.", source, "here"