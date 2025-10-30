/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision medium
 * @id py/formatted-sql-query
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */
import python
import semmle.python.ApiGraphs
import DataFlow::PathGraph
import semmle.python.dataflow.TaintTracking

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(Call call |
      call = this.asExpr() and
      (
        call.getLocation().getFile().getRelativePath().toString().regexpMatches("\\.\\.\\.\\s*%\\.\\.\\.") or
        call.getCallee().getQualifiedName().regexpMatches(".*\\.format")
      )
    ) or
    exists(StringLiteral str |
      str = this.asExpr() and
      str.getValue().matches("f\"%")
    )
  }

  override predicate hasLocationInfo() { any() }
  override string toString() { result = "SQL format source" }
}

class SqlExecuteSink extends DataFlow::Node {
  SqlExecuteSink() {
    exists(Call call |
      call = this.asExpr() and
      call.getCallee().getName() = "execute" and
      this.asExpr() = call.getArg(0)
    )
  }

  override predicate hasLocationInfo() { any() }
  override string toString() { result = "SQL execute sink" }
}

class SqlTaintConfig extends TaintTracking::Configuration {
  SqlTaintConfig() { this = "SqlTaintConfig" }

  override predicate isSource(TaintTracking::TaintSource source) {
    source instanceof SqlFormatSource
  }

  override predicate isSink(TaintTracking::TaintSink sink) {
    sink instanceof SqlExecuteSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Call call |
      pred.asExpr() = call.getAnArgument() and
      succ.asExpr() = call
    )
  }
}

from SqlTaintConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, "Detected possible formatted SQL query. Use parameterized queries instead.", 
  source, "Potential SQL formatting operation here"