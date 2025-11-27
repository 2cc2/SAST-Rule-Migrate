/**
 * @name Construction of a cookie using user-supplied input
 * @description Constructing cookies from user input may allow an attacker to perform a Cookie Poisoning attack.
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @security-severity 5.0
 * @id py/cookie-injection
 * @tags security
 *       external/cwe/cwe-020
 */

import python

// Core dataflow / taint-tracking libraries
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

// Optional helpers used by some customizations (kept for compatibility)
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources

// HTTP cookie write helper used by the CookieWriteSink below
// (this import matches existing CodeQL Python libraries where Http::Server::CookieWrite is defined)
import Http

/**
 * Inlined customizations for cookie-injection (equivalent to CookieInjectionCustomizations.qll)
 *
 * Provides default sources, sinks and sanitizers for detecting
 * "cookie injection" vulnerabilities, as well as extension points for adding your own.
 */
module CookieInjection {
  /**
   * A data flow source for "cookie injection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "cookie injection" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "cookie injection" vulnerabilities.
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
   * A write to a cookie, considered as a sink.
   */
  class CookieWriteSink extends Sink {
    CookieWriteSink() {
      exists(Http::Server::CookieWrite cw |
        this = [cw.getNameArg(), cw.getValueArg(), cw.getHeaderArg()]
      )
    }
  }
}

/**
 * Inlined taint-tracking configuration for cookie-injection (equivalent to CookieInjectionQuery.qll)
 *
 * A taint-tracking configuration for detecting "cookie injection" vulnerabilities.
 */
module CookieInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof CookieInjection::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof CookieInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof CookieInjection::Sanitizer }

  // Keep the incremental observer behavior the same as the original qll.
  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "cookie injection" vulnerabilities. */
module CookieInjectionFlow = TaintTracking::Global<CookieInjectionConfig>;

// Make PathGraph/PathNode types available (provided by the TaintTracking/DataFlow machinery)
import CookieInjectionFlow::PathGraph

from CookieInjectionFlow::PathNode source, CookieInjectionFlow::PathNode sink
where CookieInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Cookie is constructed from a $@.", source.getNode(),
  "user-supplied input"
