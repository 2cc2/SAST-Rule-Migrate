/**
 * @name XML internal entity expansion
 * @description Parsing user input as an XML document with arbitrary internal
 *              entity expansion is vulnerable to denial-of-service attacks.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id py/xml-bomb
 * @tags security
 *       external/cwe/cwe-776
 *       external/cwe/cwe-400
 */

import python
// import semmle.python.security.dataflow.XmlBombQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/XmlBombQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting "XML bomb" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `Configuration` is needed, otherwise
 * `XmlBombCustomizations` should be imported instead.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// import XmlBombCustomizations::XmlBomb
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/XmlBombCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "XML bomb"
 * vulnerabilities, as well as extension points for adding your own.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources

/**
 * Provides default sources, sinks and sanitizers for detecting "XML bomb"
 * vulnerabilities, as well as extension points for adding your own.
 */
module XmlBomb {
  /**
   * A data flow source for XML-bomb vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for XML-bomb vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for XML-bomb vulnerabilities.
   */
  abstract class Sanitizer extends DataFlow::Node { }

  /** A source of remote user input, considered as a flow source for XML bomb vulnerabilities. */
  class RemoteFlowSourceAsSource extends Source instanceof RemoteFlowSource { }

  /**
   * A call to an XML parser that is vulnerable to XML bombs.
   */
  class XmlParsingVulnerableToXmlBomb extends Sink {
    XmlParsingVulnerableToXmlBomb() {
      exists(XML::XmlParsing parsing, XML::XmlParsingVulnerabilityKind kind |
        kind.isXmlBomb() and
        parsing.vulnerableTo(kind) and
        this = parsing.getAnInput()
      )
    }
  }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/XmlBombCustomizations.qll ---

private module XmlBombConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "XML bomb" vulnerabilities. */
module XmlBombFlow = TaintTracking::Global<XmlBombConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/XmlBombQuery.qll ---
// import XmlBombFlow::PathGraph

from XmlBombFlow::PathNode source, XmlBombFlow::PathNode sink
where XmlBombFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "XML parsing depends on a $@ without guarding against uncontrolled entity expansion.",
  source.getNode(), "user-provided value"
