/**
 * @name Polynomial regular expression used on uncontrolled data
 * @description A regular expression that can require polynomial time
 *              to match may be vulnerable to denial-of-service attacks.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id py/polynomial-redos
 * @tags security
 *       external/cwe/cwe-1333
 *       external/cwe/cwe-730
 *       external/cwe/cwe-400
 */

import python
// import semmle.python.security.dataflow.PolynomialReDoSQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/PolynomialReDoSQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting "polynomial regular expression denial of service (ReDoS)" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `PolynomialReDoS::Configuration` is needed, otherwise
 * `PolynomialReDoSCustomizations` should be imported instead.
 */

private import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// import PolynomialReDoSCustomizations::PolynomialReDoS
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/PolynomialReDoSCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "polynomial regular expression denial of service (ReDoS)"
 * vulnerabilities, as well as extension points for adding your own.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards
private import semmle.python.regexp.RegexTreeView::RegexTreeView as TreeView
private import semmle.python.ApiGraphs
private import semmle.python.regex

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "polynomial regular expression denial of service (ReDoS)"
 * vulnerabilities, as well as extension points for adding your own.
 */
module PolynomialReDoS {
  private import TreeView
  import codeql.regex.nfa.SuperlinearBackTracking::Make<TreeView>

  /**
   * A data flow source for "polynomial regular expression denial of service (ReDoS)" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "polynomial regular expression denial of service (ReDoS)" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node {
    /** Gets the regex that is being executed by this node. */
    abstract RegExpTerm getRegExp();

    /** Gets a term within the regexp that may perform polynomial back-tracking. */
    final PolynomialBackTrackingTerm getABacktrackingTerm() {
      result.getRootTerm() = this.getRegExp()
    }

    /**
     * Gets the node to highlight in the alert message.
     */
    DataFlow::Node getHighlight() { result = this }
  }

  /**
   * A sanitizer for "polynomial regular expression denial of service (ReDoS)" vulnerabilities.
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
   * A regex execution, considered as a flow sink.
   */
  class RegexExecutionAsSink extends Sink {
    RegExpTerm t;

    RegexExecutionAsSink() {
      exists(RegexExecution re |
        t = getTermForExecution(re) and
        this = re.getString()
      ) and
      t.isRootTerm()
    }

    /** Gets the regex that is being executed by this node. */
    override RegExpTerm getRegExp() { result = t }
  }

  /**
   * A comparison with a constant, considered as a sanitizer-guard.
   */
  class ConstCompareAsSanitizerGuard extends Sanitizer, ConstCompareBarrier { }

  /** DEPRECATED: Use ConstCompareAsSanitizerGuard instead. */
  deprecated class StringConstCompareAsSanitizerGuard = ConstCompareAsSanitizerGuard;
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/PolynomialReDoSCustomizations.qll ---

private module PolynomialReDoSConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }

  Location getASelectedSinkLocation(DataFlow::Node sink) {
    result = sink.(Sink).getLocation()
    or
    result = sink.(Sink).getHighlight().getLocation()
    or
    result = sink.(Sink).getABacktrackingTerm().getLocation()
  }
}

/** Global taint-tracking for detecting "polynomial regular expression denial of service (ReDoS)" vulnerabilities. */
module PolynomialReDoSFlow = TaintTracking::Global<PolynomialReDoSConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/PolynomialReDoSQuery.qll ---
// import PolynomialReDoSFlow::PathGraph

from
  PolynomialReDoSFlow::PathNode source, PolynomialReDoSFlow::PathNode sink, Sink sinkNode,
  PolynomialBackTrackingTerm regexp
where
  PolynomialReDoSFlow::flowPath(source, sink) and
  sinkNode = sink.getNode() and
  regexp = sinkNode.getABacktrackingTerm()
//   not (
//     source.getNode().(Source).getKind() = "url" and
//     regexp.isAtEndLine()
//   )
select sinkNode.getHighlight(), source, sink,
  "This $@ that depends on a $@ may run slow on strings " + regexp.getPrefixMessage() +
    "with many repetitions of '" + regexp.getPumpString() + "'.", regexp, "regular expression",
  source.getNode(), "user-provided value"
