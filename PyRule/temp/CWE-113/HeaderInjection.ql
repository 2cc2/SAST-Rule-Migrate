/**
 * @name HTTP Response Splitting
 * @description Writing user input directly to an HTTP header
 *              makes code vulnerable to attack by header splitting.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id py/http-response-splitting
 * @tags security
 *       external/cwe/cwe-113
 *       external/cwe/cwe-079
 */

import python
// import semmle.python.security.dataflow.HttpHeaderInjectionQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/HttpHeaderInjectionQuery.qll ---
/**
 * Provides a taint tracking configuration for reasoning about HTTP header injection.
 */

import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
// private import HttpHeaderInjectionCustomizations
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/HttpHeaderInjectionCustomizations.qll ---
/**
 * Provides default sources, sinks, and sanitizers for detecting
 * "HTTP Header injection" vulnerabilities, as well as extension
 * points for adding your own.
 */

import python
private import semmle.python.Concepts
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.dataflow.new.RemoteFlowSources

/**
 * Provides default sources, sinks, and sanitizers for detecting
 * "HTTP Header injection" vulnerabilities, as well as extension
 * points for adding your own.
 */
module HttpHeaderInjection {
  /**
   * A data flow source for "HTTP Header injection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "HTTP Header injection" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A data flow sanitizer for "HTTP Header injection" vulnerabilities.
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
   * A HTTP header write, considered as a flow sink.
   */
  class HeaderWriteAsSink extends Sink {
    HeaderWriteAsSink() {
      exists(Http::Server::ResponseHeaderWrite headerWrite |
        headerWrite.nameAllowsNewline() and
        this = headerWrite.getNameArg()
        or
        headerWrite.valueAllowsNewline() and
        this = headerWrite.getValueArg()
      )
    }
  }

  /**
   * A call to replace line breaks, considered as a sanitizer.
   */
  class ReplaceLineBreaksSanitizer extends Sanitizer, DataFlow::CallCfgNode {
    ReplaceLineBreaksSanitizer() {
      this.getFunction().(DataFlow::AttrRead).getAttributeName() = "replace" and
      this.getArg(0).asExpr().(StringLiteral).getText() = "\n"
    }
  }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/HttpHeaderInjectionCustomizations.qll ---

/**
 * A taint-tracking configuration for detecting HTTP Header injection vulnerabilities.
 */
private module HeaderInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof HttpHeaderInjection::Source }

  predicate isSink(DataFlow::Node node) { node instanceof HttpHeaderInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof HttpHeaderInjection::Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "HTTP Header injection" vulnerabilities. */
module HeaderInjectionFlow = TaintTracking::Global<HeaderInjectionConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/HttpHeaderInjectionQuery.qll ---
// import HeaderInjectionFlow::PathGraph

from HeaderInjectionFlow::PathNode source, HeaderInjectionFlow::PathNode sink
where HeaderInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This HTTP header is constructed from a $@.", source.getNode(),
  "user-provided value"
