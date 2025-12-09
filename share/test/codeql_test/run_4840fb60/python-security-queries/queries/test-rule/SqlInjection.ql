/**
 * @name SQL query built from user-controlled sources
 * @description Building a SQL query from user-controlled sources is vulnerable to insertion of
 *              malicious SQL code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id py/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */
import python 
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards
module SqlInjection {
  abstract class Source extends DataFlow::Node { }
  abstract class Sink extends DataFlow::Node { }
  abstract class Sanitizer extends DataFlow::Node { }
  private class ActiveThreatModelSourceAsSource extends Source, ActiveThreatModelSource { }
  
  class SqlConstructionAsSink extends Sink {
    SqlConstructionAsSink() { this = any(SqlConstruction c).getSql() }
  }

  class SqlExecutionAsSink extends Sink {
    SqlExecutionAsSink() { this = any(SqlExecution e).getSql() }
  }

  class ConstCompareAsSanitizerGuard extends Sanitizer, ConstCompareBarrier { }
  private import semmle.python.frameworks.data.ModelsAsData
  private class DataAsSqlSink extends Sink {
    DataAsSqlSink() { this = ModelOutput::getASinkNode("sql-injection").asSink() }
  }
}

private module SqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SqlInjection::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof SqlInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "SQL injection" vulnerabilities. */
module SqlInjectionFlow = TaintTracking::Global<SqlInjectionConfig>;




from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on a $@.", source.getNode(),
  "user-provided value"
 