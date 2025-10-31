/**
 * @name SQL Injection in SQLAlchemy queries
 * @description Detects SQL injection vulnerabilities in SQLAlchemy distinct, 
 *              having, group_by, order_by, and filter clauses with raw SQL
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.0
 * @precision high
 * @id py/sqlalchemy-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.security.injection.SqlInjection
import semmle.python.web.HttpRequest
import DataFlow::PathGraph

predicate isSource(DataFlow::Node source) {
  exists(string funcName, string paramName |
    source.asParameter().getFunction().getName() = funcName and
    source.asParameter().getName() = paramName
  )
}

predicate isSink(DataFlow::Node sink) {
  exists(string methodName |
    sink = any(Call call |
      call.getCalleeName().regexpMatch("(group_by|order_by|distinct|having|filter)") and
      not call.getQualifier().getCalleeName().regexpMatch("bindparams") and
      call.getAnArgument(0).getCalleeName().matches("%FORMATFUNC%")
    ).getAUse()
  )
}

predicate isSanitizer(DataFlow::Node sanitizer) {
  exists(Call call |
    call.getCalleeName() = "bindparams" and
    sanitizer = call.getAUse()
  )
}

module TaintTrackingConfig implements TaintTracking::Config {
  predicate isSource(DataFlow::Node source) { isSource(source) }
  predicate isSink(DataFlow::Node sink) { isSink(sink) }
  predicate isSanitizer(DataFlow::Node sanitizer) { isSanitizer(sanitizer) }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintTrackingConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potentially unsafe SQL injection in SQLAlchemy query"