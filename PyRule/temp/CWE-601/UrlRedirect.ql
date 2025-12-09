/**
 * @name URL redirection from remote source
 * @description URL redirection based on unvalidated user input
 *              may cause redirection to malicious web sites.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @sub-severity low
 * @id py/url-redirection
 * @tags security
 *       external/cwe/cwe-601
 * @precision high
 */

import python
// import semmle.python.security.dataflow.UrlRedirectQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/UrlRedirectQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting "URL redirection" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `UrlRedirect::Configuration` is needed, otherwise
 * `UrlRedirectCustomizations` should be imported instead.
 */

private import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// import UrlRedirectCustomizations::UrlRedirect as UrlRedirect
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/UrlRedirectCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "URL redirection"
 * vulnerabilities, as well as extension points for adding your own.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards
private import semmle.python.frameworks.data.ModelsAsData

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "URL redirection"
 * vulnerabilities, as well as extension points for adding your own.
 */
module UrlRedirect {
  /**
   * A state value to track whether the untrusted data may contain backslashes.
   */
  abstract class FlowState extends string {
    bindingset[this]
    FlowState() { any() }
  }

  /**
   * A state value signifying that the untrusted data may contain backslashes.
   */
  class MayContainBackslashes extends UrlRedirect::FlowState {
    MayContainBackslashes() { this = "MayContainBackslashes" }
  }

  /**
   * A state value signifying that any backslashes in the untrusted data have
   * been eliminated, but no other sanitization has happened.
   */
  class NoBackslashes extends UrlRedirect::FlowState {
    NoBackslashes() { this = "NoBackslashes" }
  }

  /**
   * A data flow source for "URL redirection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "URL redirection" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "URL redirection" vulnerabilities.
   */
  abstract class Sanitizer extends DataFlow::Node {
    /**
     * Holds if this sanitizer sanitizes flow in the given state.
     */
    abstract predicate sanitizes(FlowState state);
  }

  /**
   * An additional flow step for "URL redirection" vulnerabilities.
   */
  abstract class AdditionalFlowStep extends DataFlow::Node {
    /**
     * Holds if there should be an additional flow step from `nodeFrom` in `stateFrom`
     * to `nodeTo` in `stateTo`.
     *
     * For example, a call to `replace` that replaces backslashes with forward slashes
     * takes flow from `MayContainBackslashes` to `NoBackslashes`.
     */
    abstract predicate step(
      DataFlow::Node nodeFrom, FlowState stateFrom, DataFlow::Node nodeTo, FlowState stateTo
    );
  }

  /**
   * DEPRECATED: Use `ActiveThreatModelSource` from Concepts instead!
   */
  deprecated class RemoteFlowSourceAsSource = ActiveThreatModelSourceAsSource;

  /**
   * An active threat-model source, considered as a flow source.
   */
  private class ActiveThreatModelSourceAsSource extends Source, ActiveThreatModelSource { }

  /**
   * A HTTP redirect response, considered as a flow sink.
   */
  class RedirectLocationAsSink extends Sink {
    RedirectLocationAsSink() {
      this = any(Http::Server::HttpRedirectResponse e).getRedirectLocation()
    }
  }

  private class SinkFromModel extends Sink {
    SinkFromModel() { this = ModelOutput::getASinkNode("url-redirection").asSink() }
  }

  /**
   * The right side of a string-concat, considered as a sanitizer.
   */
  class StringConcatAsSanitizer extends Sanitizer {
    StringConcatAsSanitizer() {
      // Url redirection is a problem only if the user controls the prefix of the URL.
      // TODO: This is a copy of the taint-sanitizer from the old points-to query, which doesn't
      // cover formatting.
      exists(BinaryExprNode string_concat | string_concat.getOp() instanceof Add |
        string_concat.getRight() = this.asCfgNode()
      )
    }

    override predicate sanitizes(FlowState state) {
      // sanitize all flow states
      any()
    }
  }

  /**
   * A call that replaces backslashes with forward slashes or eliminates them
   * altogether, considered as a partial sanitizer, as well as an additional
   * flow step.
   */
  class ReplaceBackslashesSanitizer extends Sanitizer, AdditionalFlowStep, DataFlow::MethodCallNode {
    DataFlow::Node receiver;

    ReplaceBackslashesSanitizer() {
      this.calls(receiver, "replace") and
      this.getArg(0).asExpr().(StringLiteral).getText() = "\\" and
      this.getArg(1).asExpr().(StringLiteral).getText() in ["/", ""]
    }

    override predicate sanitizes(FlowState state) { state instanceof MayContainBackslashes }

    override predicate step(
      DataFlow::Node nodeFrom, FlowState stateFrom, DataFlow::Node nodeTo, FlowState stateTo
    ) {
      nodeFrom = receiver and
      stateFrom instanceof MayContainBackslashes and
      nodeTo = this and
      stateTo instanceof NoBackslashes
    }
  }

  /**
   * A comparison with a constant, considered as a sanitizer-guard.
   */
  class ConstCompareAsSanitizerGuard extends Sanitizer, ConstCompareBarrier {
    override predicate sanitizes(FlowState state) {
      // sanitize all flow states
      any()
    }
  }

  /** DEPRECATED: Use ConstCompareAsSanitizerGuard instead. */
  deprecated class StringConstCompareAsSanitizerGuard = ConstCompareAsSanitizerGuard;
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/UrlRedirectCustomizations.qll ---

private module UrlRedirectConfig implements DataFlow::StateConfigSig {
  class FlowState = UrlRedirect::FlowState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    source instanceof UrlRedirect::Source and state instanceof UrlRedirect::MayContainBackslashes
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    sink instanceof UrlRedirect::Sink and
    exists(state)
  }

  predicate isBarrier(DataFlow::Node node, FlowState state) {
    node.(UrlRedirect::Sanitizer).sanitizes(state)
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node nodeFrom, FlowState stateFrom, DataFlow::Node nodeTo, FlowState stateTo
  ) {
    any(UrlRedirect::AdditionalFlowStep a).step(nodeFrom, stateFrom, nodeTo, stateTo)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "URL redirection" vulnerabilities. */
module UrlRedirectFlow = TaintTracking::GlobalWithState<UrlRedirectConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/UrlRedirectQuery.qll ---
// import UrlRedirectFlow::PathGraph

from UrlRedirectFlow::PathNode source, UrlRedirectFlow::PathNode sink
where UrlRedirectFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted URL redirection depends on a $@.", source.getNode(),
  "user-provided value"
