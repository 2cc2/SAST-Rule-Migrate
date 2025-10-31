/**
 * @name asyncpg-sqli
 * @description Detected string concatenation with a non-literal variable in a asyncpg Python SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead.
 * @kind taint
 * @problem.severity warning
 * @id py/asyncpg-sqli
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.dataflow.FlowSources
import semmle.python.ApiGraphs
import semmle.python.Concepts

class AsyncPgSqlSources extends DataFlow::Node::Range {
  AsyncPgSqlSources() {
    this.asStringLiteral()
  }
}

class AsyncPgSqlSink extends DataFlow::Node::Range {
  AsyncPgSqlSink() {
    exists(MethodCall call |
      call.getMethodName().regexpMatch("(fetch|fetchrow|fetchval|execute|executemany|prepare|cursor|copyfromquery)") and
      call.getQualifier().getStrippedQualifiedName() = "asyncpg" and
      call.getAnArgument() = this and
      this.asString().regexpMatch(".*\\+.*|.*\\..*format\\(.*\\)|.*%.*\\(.*\\)|f'.*\\{.*\\}.*'")
    )
  }
}

class ParameterizedQuerySanitizer extends DataFlow::Node::Range {
  ParameterizedQuerySanitizer() {
    exists(MethodCall call |
      call.getMethodName().regexpMatch("(fetch|fetchrow|fetchval|execute|executemany|prepare|cursor|copyfromquery)") and
      call.getQualifier().getStrippedQualifiedName() = "asyncpg" and
      call.getAnArgument() = this and
      this.asString().regexpMatch("^\\$[0-9]+$")
    )
  }
}

class AsyncPgSqlFlowConfiguration extends TaintTracking::Configuration {
  AsyncPgSqlFlowConfiguration() { this = "AsyncPgSqlFlow" }

  override predicate isSource(DataFlow::Node source) { source instanceof AsyncPgSqlSources }

  override predicate isSink(DataFlow::Node sink) { sink instanceof AsyncPgSqlSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof ParameterizedQuerySanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(FunctionArgument arg, Parameter param |
      arg.getFunction() = param.getFunction() and
      succ = arg.getNode() and
      pred = param.getNode()
    )
  }
}

from AsyncPgSqlFlowConfiguration config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential SQL injection through string concatenation in asyncpg call. $@", source,
  "User input flows into SQL query here"