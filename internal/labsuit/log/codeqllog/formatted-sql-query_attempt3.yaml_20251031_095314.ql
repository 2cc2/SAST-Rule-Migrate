import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private class SqlFormatSource extends DataFlow::Node::Source {
  SqlFormatSource() {
    exists(Call c |
      (
        c.getCallee().toString().regexpMatch(".*\\.format") or
        c.getAnArgument().regexpMatch("\\%\\.\\.\\.")
      ) and
      this.asExpr() = c
    )
    or
    (
      exists(DataFlow::BasicBlock::Expr e |
        e instanceof StringLiteral and
        e.toString().matches("%f\"%") and
        this.asExpr() = e
      )
    )
  }

  override predicate isSourceOf(DataFlow::Node node) {
    this = node
  }
}

private class SqlExecutionSink extends DataFlow::Node::Sink {
  SqlExecutionSink() {
    exists(Call c |
      c.getCallee().toString() = "execute" and
      this.asExpr() = c.getAnArgument(0)
    )
  }

  override predicate isSink(DataFlow::Node node) {
    this = node
  }
}

class SqlTaintConfiguration extends TaintTracking::Configuration {
  SqlTaintConfiguration() { this = "SqlTaintConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlFormatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }
}

from SqlTaintConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, "Detected possible formatted SQL query. Use parameterized queries instead."