/**
 * @name Uncontrolled data used in path expression
 * @description Accessing paths influenced by users can allow an attacker to access unexpected resources.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @sub-severity high
 * @precision high
 * @id py/path-injection
 * @tags correctness
 *       security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 *       external/cwe/cwe-099
 */

import python
import semmle.python.security.dataflow.PathInjectionQuery
import PathInjectionFlow::PathGraph
private import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import PathInjectionCustomizations::PathInjection


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




abstract private class NormalizationState extends string {
    bindingset[this]
    NormalizationState() { any() }
}
 
 /** A state signifying that the file path has not been normalized. */
class NotNormalized extends NormalizationState {
    NotNormalized() { this = "NotNormalized" }
}
 
 /** A state signifying that the file path has been normalized, but not checked. */
class NormalizedUnchecked extends NormalizationState {
    NormalizedUnchecked() { this = "NormalizedUnchecked" }
}
 
 /**
  * This configuration uses two flow states, `NotNormalized` and `NormalizedUnchecked`,
  * to track the requirement that a file path must be first normalized and then checked
  * before it is safe to use.
  *
  * At sources, paths are assumed not normalized. At normalization points, they change
  * state to `NormalizedUnchecked` after which they can be made safe by an appropriate
  * check of the prefix.
  *
  * Such checks are ineffective in the `NotNormalized` state.
  */
module PathInjectionConfig implements DataFlow::StateConfigSig {
    class FlowState = NormalizationState;
 
    predicate isSource(DataFlow::Node source, FlowState state) {
        source instanceof SqlInjection::Source and state instanceof NotNormalized
    }
 
    predicate isSink(DataFlow::Node sink, FlowState state) {
    sink instanceof SqlInjection::Sink and
    (
        state instanceof NotNormalized or
        state instanceof NormalizedUnchecked
    )
    }
 
    predicate isBarrier(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }
 
    predicate isBarrier(DataFlow::Node node, FlowState state) {
     // Block `NotNormalized` paths here, since they change state to `NormalizedUnchecked`
    node instanceof Path::PathNormalization and
    state instanceof NotNormalized
    or
    node instanceof Path::SafeAccessCheck and
    state instanceof NormalizedUnchecked
    }
 
   predicate isAdditionalFlowStep(
    DataFlow::Node nodeFrom, FlowState stateFrom, DataFlow::Node nodeTo, FlowState stateTo
    ) {
    nodeFrom = nodeTo.(Path::PathNormalization).getPathArg() and
    stateFrom instanceof NotNormalized and
    stateTo instanceof NormalizedUnchecked
    }
 
   predicate observeDiffInformedIncrementalMode() { any() }
 }
 
 /** Global taint-tracking for detecting "path injection" vulnerabilities. */
module PathInjectionFlow = TaintTracking::GlobalWithState<PathInjectionConfig>;
  
from PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink
where PathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This path depends on a $@.", source.getNode(),
    "user-provided value"
 