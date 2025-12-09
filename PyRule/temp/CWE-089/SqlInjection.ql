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
// import semmle.python.security.dataflow.SqlInjectionQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/SqlInjectionQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting "SQL injection" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `SqlInjection::Configuration` is needed, otherwise
 * `SqlInjectionCustomizations` should be imported instead.
 */

private import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// import SqlInjectionCustomizations::SqlInjection
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/SqlInjectionCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "SQL injection"
 * vulnerabilities, as well as extension points for adding your own.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "SQL injection"
 * vulnerabilities, as well as extension points for adding your own.
 */
module SqlInjection {
  /**
   * A data flow source for "SQL injection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "SQL injection" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "SQL injection" vulnerabilities.
   */
  abstract class Sanitizer extends DataFlow::Node { }

  /**
   * DEPRECATED: Use `ActiveThreatModelSource` from Concepts instead!
   */
  deprecated class RemoteFlowSourceAsSource = ActiveThreatModelSourceAsSource;

  /**
   * An active threat-model source, considered as a flow source.
   */
  private class ActiveThreatModelSourceAsSource extends Source, ActiveThreatModelSource { }

  /**
   * A SQL statement of a SQL construction, considered as a flow sink.
   */
  class SqlConstructionAsSink extends Sink {
    SqlConstructionAsSink() { this = any(SqlConstruction c).getSql() }
  }

  /**
   * A SQL statement of a SQL execution, considered as a flow sink.
   */
  class SqlExecutionAsSink extends Sink {
    SqlExecutionAsSink() { this = any(SqlExecution e).getSql() }
  }

  /**
   * A comparison with a constant, considered as a sanitizer-guard.
   */
  class ConstCompareAsSanitizerGuard extends Sanitizer, ConstCompareBarrier { }

  /** DEPRECATED: Use ConstCompareAsSanitizerGuard instead. */
  deprecated class StringConstCompareAsSanitizerGuard = ConstCompareAsSanitizerGuard;

  private import semmle.python.frameworks.data.ModelsAsData

  /** A sink for sql-injection from model data. */
  private class DataAsSqlSink extends Sink {
    DataAsSqlSink() { this = ModelOutput::getASinkNode("sql-injection").asSink() }
  }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/SqlInjectionCustomizations.qll ---

private module SqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "SQL injection" vulnerabilities. */
module SqlInjectionFlow = TaintTracking::Global<SqlInjectionConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/SqlInjectionQuery.qll ---
// import SqlInjectionFlow::PathGraph

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on a $@.", source.getNode(),
  "user-provided value"
