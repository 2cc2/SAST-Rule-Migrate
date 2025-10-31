/**
 * @name SQLAlchemy SQL Injection
 * @description Distinct, Having, Group_by, Order_by, and Filter in SQLAlchemy can cause 
 *   SQL injections if the developer inputs raw SQL into the before-mentioned clauses.
 * @kind problem
 * @problem.severity warning
 * @id python/sqlalchemy-sql-injection
 * @security-severity 8.8
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 *       frameworks/sqlalchemy
 */

import python
import semmle.python.security.TaintTracking

class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    exists(Function f | 
      f.getName().regexpMatch("^$FUNC$") and
      this.asParameter().getName() = "$VAR" and
      this.asParameter().getFunction() = f
    )
  }
}

class SqlInjectionSink extends DataFlow::Node {
  SqlInjectionSink() {
    exists(MethodCall mc |
      mc.getMethodName().regexpMatch("(group_by|order_by|distinct|having|filter)") and
      not mc.getQualifier().getMethodName().regexpMatch("bindparams") and
      mc.getArgument(0).getValue().getMethodName().regexpMatch("$FORMATFUNC$") and
      mc.getTarget().getQualifiedName().matches("sqlalchemy.orm.query.%") and
      this.asExpr() = mc
    )
  }
}

class BindParamsSanitizer extends DataFlow::BarrierNode {
  BindParamsSanitizer() {
    exists(MethodCall mc | mc.getMethodName() = "bindparams" and this.asExpr() = mc)
  }
}

from UserInputSource source, SqlInjectionSink sink
where DataFlow::flow(source, sink, false, [BindParamsSanitizer]) and
  not DataFlow::flow(source, sink, false, [])
select sink, "Potential SQL injection vulnerability in SQLAlchemy clause. " +
  "Use bindparams to securely bind user-input to SQL statements."