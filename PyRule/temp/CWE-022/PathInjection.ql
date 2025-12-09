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

private import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards

/**
 * Provides default sources, and sinks for detecting
 * "path injection"
 * vulnerabilities, as well as extension points for adding your own.
 *
 * Since the path-injection configuration setup is rather complicated, we do not
 * expose a `Sanitizer` class, and instead you should extend
 * `Path::PathNormalization::Range` and `Path::SafeAccessCheck::Range` from
 * `semmle.python.Concepts` instead.
 */
module PathInjection {
  /**
   * A data flow source for "path injection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "path injection" vulnerabilities.
   * Such as a file system access.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "path injection" vulnerabilities.
   *
   * This should only be used for things like calls to library functions that perform their own
   * (correct) normalization/escaping of untrusted paths.
   *
   * Please also see `Path::SafeAccessCheck` and `Path::PathNormalization` Concepts.
   */
  abstract class Sanitizer extends DataFlow::Node { }

  // deprecated class RemoteFlowSourceAsSource = ActiveThreatModelSourceAsSource;

  /**
   * An active threat-model source, considered as a flow source.
   */
  private class ActiveThreatModelSourceAsSource extends Source, ActiveThreatModelSource { }

  /**
   * A file system access, considered as a flow sink.
   */
  class FileSystemAccessAsSink extends Sink {
    FileSystemAccessAsSink() {
      this = any(FileSystemAccess e).getAPathArgument() and
      // since implementation of Path.open in pathlib.py is like
      // ```py
      // def open(self, ...):
      //     return io.open(self, ...)
      // ```
      // any time we would report flow to the `path_obj.open` sink, we can ALSO report
      // the flow from the `self` parameter to the `io.open` sink -- obviously we
      // don't want that.
      //
      // However, simply removing taint edges out of a sink is not a good enough solution,
      // since we would only flag one of the `p.open` calls in the following example
      // due to use-use flow
      // ```py
      // p.open()
      // p.open()
      // ```
      //
      // The same approach is used in the command injection query.
      not exists(Module inStdlib |
        inStdlib.getName() in ["pathlib", "os"] and
        this.getScope().getEnclosingModule() = inStdlib and
        // do allow this call if we're analyzing, say, pathlib.py as part of CPython though
        not exists(inStdlib.getFile().getRelativePath())
      )
    }
  }

  private import semmle.python.frameworks.data.ModelsAsData

  private class DataAsFileSink extends Sink {
    DataAsFileSink() { this = ModelOutput::getASinkNode("path-injection").asSink() }
  }

  /**
   * A comparison with a constant, considered as a sanitizer-guard.
   */
  class ConstCompareAsSanitizerGuard extends Sanitizer, ConstCompareBarrier { }

  // deprecated class StringConstCompareAsSanitizerGuard = ConstCompareAsSanitizerGuard;
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/PathInjectionCustomizations.qll ---

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
    source instanceof PathInjection::Source and state instanceof NotNormalized
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    sink instanceof PathInjection::Sink and
    (
      state instanceof NotNormalized or
      state instanceof NormalizedUnchecked
    )
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof PathInjection::Sanitizer }

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
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/PathInjectionQuery.qll ---
// import PathInjectionFlow::PathGraph
// import PathInjectionFlow::PathGraph
from PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink
where PathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This path depends on a $@.", source.getNode(),
  "user-provided value"
