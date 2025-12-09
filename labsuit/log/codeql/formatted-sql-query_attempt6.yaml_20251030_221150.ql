/**
 * @name Formatted SQL query
 * @description Detected possible formatted SQL query. Use parameterized queries instead.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.8
 * @tags security
 *       external/cwe/cwe-089
 *       owasp-a01
 *       owasp-a03
 */
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.PathGraph

class SqlFormatSource extends DataFlow::Source {
  SqlFormatSource() {
    exists(Call c |
      // SQL format with % operator
      regexMatches(c.toString(), "\\s*%\\.\\.\\.") or
      // SQL format with .format method
      regexMatches(c.getFunc().(Name).getName(), ".*\\.format") or
      // SQL format with f-string
      exists(Literal lit | 
        lit = c.getArg(0) and 
        lit.toString().matches("f\"")
      )
    )
  }

  override predicate isSourceOf(DataFlow::Node source) { 
    source.asExpr() = this and
    exists(Call c |
      c = source.asExpr() and
      (
        regexMatches(c.toString(), "\\s*%\\.\\.\\.") or
        regexMatches(c.getFunc().(Name).getName(), ".*\\.format") or
        exists(Literal lit | 
          lit = c.getArg(0) and 
          lit.toString().matches("f\"")
        )
      )
    )
  }
}

class SqlExecutionSink extends DataFlow::Sink {
  SqlExecutionSink() { 
    exists(Call c | 
      c.getFunc().(Name).getName() = "execute" and
      c.getArg(0) = this.asExpr()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = this and
    exists(Call c | 
      c = sink.asExpr() and
      c.getFunc().(Name).getName() = "execute"
    )
  }
}

class SqlInjectionConfig extends DataFlow::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) { 
    source instanceof SqlFormatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlExecutionSink
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, SqlInjectionConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected possible formatted SQL query. Use parameterized queries instead."