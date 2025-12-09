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
import CookieInjectionFlow::PathGraph
// private import python
// import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

// private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "cookie injection"
 * vulnerabilities, as well as extension points for adding your own.
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

//   deprecated class RemoteFlowSourceAsSource = ActiveThreatModelSourceAsSource;

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
 * A taint-tracking configuration for detecting "cookie injection" vulnerabilities.
 */
module CookieInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof CookieInjection::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof CookieInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof CookieInjection::Sanitizer }
  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "cookie injection" vulnerabilities. */
module CookieInjectionFlow = TaintTracking::Global<CookieInjectionConfig>;



from CookieInjectionFlow::PathNode source, CookieInjectionFlow::PathNode sink
where CookieInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Cookie is constructed from a $@.", source.getNode(),
  "user-supplied input"