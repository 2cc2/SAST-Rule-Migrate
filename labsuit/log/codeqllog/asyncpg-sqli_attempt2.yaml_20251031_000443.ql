/**
 * @name AsyncPG SQL injection vulnerability
 * @description Detected string concatenation with a non-literal variable in a asyncpg Python SQL statement.
 * @kind path-problem
 * @problem.severity warning
 * @id python/asyncpg-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.security.TaintTracking
import DataFlow::PathGraph
import semmle.python.CallGraph

class AsyncPgSqlSource extends DataFlow::Node {
  AsyncPgSqlSource() {
    exists(string val | this.asStringLiteral().getValue() = val)
  }
}

class AsyncPgSqlSink extends DataFlow::Node {
  AsyncPgSqlSink() {
    exists(MethodCall call |
      call.getMethodName().regexpMatch("(fetch|fetchrow|fetchval|execute|executemany|prepare|cursor|copyfromquery)") and
      call.getTarget().getQualifiedName() = "asyncpg" and
      this = call.getArgument(0) and
      this.asExpr().toString().regexpMatch(".*\\+.*|.*\\..*format\\(.*\\)|.*%.*\\(.*\\)|f'.*\\{.*\\}.*'")
    )
  }
}

class ParameterizedQuerySanitizer extends DataFlow::Node {
  ParameterizedQuerySanitizer() {
    exists(MethodCall call |
      call.getMethodName().regexpMatch("(fetch|fetchrow|fetchval|execute|executemany|prepare|cursor|copyfromquery)") and
      call.getTarget().getQualifiedName() = "asyncpg" and
      this = call.getArgument(0) and
      this.asExpr().toString().regexpMatch("^\\$[0-9]+$")
    )
  }
}

class AsyncPgSqlTaintTracking extends TaintTracking::Configuration {
  AsyncPgSqlTaintTracking() { this = "AsyncPgSqlTaintTracking" }

  override predicate isSource(DataFlow::Node source) { source instanceof AsyncPgSqlSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof AsyncPgSqlSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof ParameterizedQuerySanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(FunctionArgument arg |
      arg = succ.asExpr() and
      arg.getParentCall().getArgument(0) = pred.asExpr()
    )
  }
}

from AsyncPgSqlTaintTracking cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected string concatenation with a non-literal variable in " +
"asyncpg SQL statement. This could lead to SQL injection if the variable is user-controlled."