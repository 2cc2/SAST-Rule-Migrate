/**
 * @name Regular expression injection
 * @description User input should not be used in regular expressions without first being escaped,
 *              otherwise a malicious user may be able to inject an expression that could require
 *              exponential time on certain inputs.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id py/regex-injection
 * @tags security
 *       external/cwe/cwe-730
 *       external/cwe/cwe-400
 */

import python
private import semmle.python.Concepts
// import semmle.python.security.dataflow.RegexInjectionQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/RegexInjectionQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting "regular expression injection"
 * vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `RegexInjection::Configuration` is needed, otherwise
 * `RegexInjectionCustomizations` should be imported instead.
 */

private import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// import RegexInjectionCustomizations::RegexInjection
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/RegexInjectionCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "regular expression injection"
 * vulnerabilities, as well as extension points for adding your own.
 */

private import python
private import semmle.python.Concepts
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.dataflow.new.RemoteFlowSources

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "regular expression injection"
 * vulnerabilities, as well as extension points for adding your own.
 */
module RegexInjection {
  /**
   * A data flow source for "regular expression injection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A sink for "regular expression injection" vulnerabilities is the execution of a regular expression.
   * If you have a custom way to execute regular expressions, you can extend `RegexExecution::Range`.
   */
  class Sink extends DataFlow::Node {
    RegexExecution regexExecution;

    Sink() { this = regexExecution.getRegex() }

    /** Gets the call that executes the regular expression marked by this sink. */
    RegexExecution getRegexExecution() { result = regexExecution }
  }

  /**
   * A sanitizer for "regular expression injection" vulnerabilities.
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
   * A regex escaping, considered as a sanitizer.
   */
  class RegexEscapingAsSanitizer extends Sanitizer {
    RegexEscapingAsSanitizer() {
      // Due to use-use flow, we want the output rather than an input
      // (so the input can still flow to other sinks).
      this = any(RegexEscaping esc).getOutput()
    }
  }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/RegexInjectionCustomizations.qll ---

private module RegexInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }

  Location getASelectedSinkLocation(DataFlow::Node sink) {
    result = sink.(Sink).getLocation()
    or
    result = sink.(Sink).getRegexExecution().getLocation()
  }
}

/** Global taint-tracking for detecting "regular expression injection" vulnerabilities. */
module RegexInjectionFlow = TaintTracking::Global<RegexInjectionConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/RegexInjectionQuery.qll ---
// import RegexInjectionFlow::PathGraph

from
  RegexInjectionFlow::PathNode source, RegexInjectionFlow::PathNode sink,
  RegexExecution regexExecution
where
  RegexInjectionFlow::flowPath(source, sink) and
  regexExecution = sink.getNode().(Sink).getRegexExecution()
select sink.getNode(), source, sink,
  "This regular expression depends on a $@ and is executed by $@.", source.getNode(),
  "user-provided value", regexExecution, regexExecution.getName()
