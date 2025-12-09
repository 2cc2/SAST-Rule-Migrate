/**
 * @name XPath query built from user-controlled sources
 * @description Building a XPath query from user-controlled sources is vulnerable to insertion of
 *              malicious Xpath code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/xpath-injection
 * @tags security
 *       external/cwe/cwe-643
 */

import python
// import semmle.python.security.dataflow.XpathInjectionQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/XpathInjectionQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting "Xpath Injection" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `XpathInjection::Configuration` is needed, otherwise
 * `XpathInjectionCustomizations` should be imported instead.
 */

private import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// import XpathInjectionCustomizations::XpathInjection
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/XpathInjectionCustomizations.qll ---
/**
 * Provides class and predicates to track external data that
 * may represent malicious xpath query objects.
 *
 * This module is intended to be imported into a taint-tracking query.
 */

private import python
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.Concepts
private import semmle.python.ApiGraphs
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards

/** Models Xpath Injection related classes and functions */
module XpathInjection {
  /**
   * A data flow source for "XPath injection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "XPath injection" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "XPath injection" vulnerabilities.
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
   * A construction of an XPath expression, considered as a sink.
   */
  class XPathConstructionArg extends Sink {
    XPathConstructionArg() { this = any(XML::XPathConstruction c).getXPath() }
  }

  /**
   * An execution of an XPath expression, considered as a sink.
   */
  class XPathExecutionArg extends Sink {
    XPathExecutionArg() { this = any(XML::XPathExecution e).getXPath() }
  }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/XpathInjectionCustomizations.qll ---

private module XpathInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "Xpath Injection" vulnerabilities. */
module XpathInjectionFlow = TaintTracking::Global<XpathInjectionConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/XpathInjectionQuery.qll ---
// import XpathInjectionFlow::PathGraph

from XpathInjectionFlow::PathNode source, XpathInjectionFlow::PathNode sink
where XpathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "XPath expression depends on a $@.", source.getNode(),
  "user-provided value"
