/**
 * @name XML external entity expansion
 * @description Parsing user input as an XML document with external
 *              entity expansion is vulnerable to XXE attacks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id py/xxe
 * @tags security
 *       external/cwe/cwe-611
 *       external/cwe/cwe-827
 */

import python
// import semmle.python.security.dataflow.XxeQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/XxeQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting "XML External Entity (XXE)" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `Configuration` is needed, otherwise
 * `XxeCustomizations` should be imported instead.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// import XxeCustomizations::Xxe
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/XxeCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "XML External Entity (XXE)"
 * vulnerabilities, as well as extension points for adding your own.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources

/**
 * Provides default sources, sinks and sanitizers for detecting "XML External Entity (XXE)"
 * vulnerabilities, as well as extension points for adding your own.
 */
module Xxe {
  /**
   * A data flow source for XXE vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for XXE vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for XXE vulnerabilities.
   */
  abstract class Sanitizer extends DataFlow::Node { }

  /** A source of remote user input, considered as a flow source for XXE vulnerabilities. */
  class RemoteFlowSourceAsSource extends Source instanceof RemoteFlowSource { }

  /**
   * A call to an XML parser that is vulnerable to XXE.
   */
  class XmlParsingVulnerableToXxe extends Sink {
    XmlParsingVulnerableToXxe() {
      exists(XML::XmlParsing parsing, XML::XmlParsingVulnerabilityKind kind |
        kind.isXxe() and
        parsing.vulnerableTo(kind) and
        this = parsing.getAnInput()
      )
    }
  }

  /**
   * An XML escaping, considered as a sanitizer.
   */
  class XmlEscapingAsSanitizer extends Sanitizer {
    XmlEscapingAsSanitizer() { this = any(XmlEscaping esc).getOutput() }
  }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/XxeCustomizations.qll ---

private module XxeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "XML External Entity (XXE)" vulnerabilities. */
module XxeFlow = TaintTracking::Global<XxeConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/XxeQuery.qll ---
// import XxeFlow::PathGraph

from XxeFlow::PathNode source, XxeFlow::PathNode sink
where XxeFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "XML parsing depends on a $@ without guarding against external entity expansion.",
  source.getNode(), "user-provided value"
