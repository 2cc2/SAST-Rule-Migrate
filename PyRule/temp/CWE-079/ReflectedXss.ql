/**
 * @name Reflected server-side cross-site scripting
 * @description Writing user input directly to a web page
 *              allows for a cross-site scripting vulnerability.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @sub-severity high
 * @precision high
 * @id py/reflective-xss
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import python
// import semmle.python.security.dataflow.ReflectedXssQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/ReflectedXssQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting "reflected server-side cross-site scripting" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `ReflectedXSS::Configuration` is needed, otherwise
 * `ReflectedXSSCustomizations` should be imported instead.
 */

private import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// import ReflectedXSSCustomizations::ReflectedXss
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/ReflectedXSSCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "reflected server-side cross-site scripting"
 * vulnerabilities, as well as extension points for adding your own.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.frameworks.data.ModelsAsData
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "reflected server-side cross-site scripting"
 * vulnerabilities, as well as extension points for adding your own.
 */
module ReflectedXss {
  /**
   * A data flow source for "reflected server-side cross-site scripting" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "reflected server-side cross-site scripting" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "reflected server-side cross-site scripting" vulnerabilities.
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
   * A data flow sink for "reflected cross-site scripting" vulnerabilities.
   */
  private class SinkFromModel extends Sink {
    SinkFromModel() {
      this = ModelOutput::getASinkNode(["html-injection", "js-injection"]).asSink()
    }
  }

  /**
   * The body of a HTTP response that will be returned from a server, considered as a flow sink.
   */
  class ServerHttpResponseBodyAsSink extends Sink {
    ServerHttpResponseBodyAsSink() {
      exists(Http::Server::HttpResponse response |
        response.getMimetype().toLowerCase() = "text/html" and
        this = response.getBody()
      )
    }
  }

  /**
   * An HTML escaping, considered as a sanitizer.
   */
  class HtmlEscapingAsSanitizer extends Sanitizer {
    HtmlEscapingAsSanitizer() {
      // TODO: For now, since there is not an `isSanitizingStep` member-predicate part of a
      // `TaintTracking::Configuration`, we treat the output as a taint-sanitizer. This
      // is slightly imprecise, which you can see in the `m_unsafe + SAFE` test-case in
      // python/ql/test/library-tests/frameworks/markupsafe/taint_test.py
      //
      // However, it is better than `getAnInput()`. Due to use-use flow, that would remove
      // the taint-flow to `SINK()` in `some_escape(tainted); SINK(tainted)`.
      this = any(HtmlEscaping esc).getOutput()
    }
  }

  /**
   * A comparison with a constant, considered as a sanitizer-guard.
   */
  class ConstCompareAsSanitizerGuard extends Sanitizer, ConstCompareBarrier { }

  /** DEPRECATED: Use ConstCompareAsSanitizerGuard instead. */
  deprecated class StringConstCompareAsSanitizerGuard = ConstCompareAsSanitizerGuard;
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/ReflectedXSSCustomizations.qll ---

private module ReflectedXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "reflected server-side cross-site scripting" vulnerabilities. */
module ReflectedXssFlow = TaintTracking::Global<ReflectedXssConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/ReflectedXssQuery.qll ---
// import ReflectedXssFlow::PathGraph

from ReflectedXssFlow::PathNode source, ReflectedXssFlow::PathNode sink
where ReflectedXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Cross-site scripting vulnerability due to a $@.",
  source.getNode(), "user-provided value"
