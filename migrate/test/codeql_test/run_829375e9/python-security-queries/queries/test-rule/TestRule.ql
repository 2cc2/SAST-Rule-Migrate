/**
 * @name Formatted SQL Query Detection
 * @description Detects possible formatted SQL queries and suggests using parameterized queries instead.
 * @kind path-problem
 * @problem.severity warning
 * @id python/formatted-sql-query
 */

import python
import semmle.python.Concepts
import semmle.python.web.Http

class FormattedSQLQuery extends string::Literal {
  FormattedSQLQuery() {
    this =
      regexpMatch(".*% .*|.*\\.format\\(.*|f\".*\\{.*\\}.*")
  }
}

class SQLExecutionCall extends API::Call {
  SQLExecutionCall() {
    exists(Method m |
      m.getName() = "execute" and
      this.getTarget().(Method).getAPackage().getName() = "DB" and
      this = m.getACall()
    )
  }
}

class ParameterizedQuerySanitizer extends API::Call {
  ParameterizedQuerySanitizer() {
    exists(Method m |
      m.getName() = "execute" and
      this.getTarget().(Method).getAPackage().getName() = "DB" and
      this = m.getACall() and
      not this.getArgument(0).(string::Literal).getText() =
        regexpMatch(".*% .*|.*\\.format\\(.*|f\".*\\{.*\\}.*")
    )
  }
}

query predicate edges(DataFlow::Node source, DataFlow::Node sink) {
  exists(FormattedSQLQuery sql |
    source = sql.getAValue() and
    exists(SQLExecutionCall call |
      sink = call.getArgument(0).getAValue()
    ) and
    not exists(ParameterizedQuerySanitizer sanitizer |
      sanitizer.getArgument(0).getAValue() = source
    )
  )
}

from DataFlow::Node source, DataFlow::Node sink
where 
  edges(source, sink)
select sink, "Formatted SQL query detected, use parameterized queries instead", source,
  "Formatted string used as SQL query"