/**
 * @name LDAP query built from user-controlled sources
 * @description Building an LDAP query from user-controlled sources is vulnerable to insertion of
 *              malicious LDAP code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/ldap-injection
 * @tags security
 *       external/cwe/cwe-090
 */

// Determine precision above
import python
// import semmle.python.security.dataflow.LdapInjectionQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/LdapInjectionQuery.qll ---
/**
 * Provides taint-tracking configurations for detecting LDAP injection vulnerabilities
 *
 * Note, for performance reasons: only import this file if
 * `LdapInjection::Configuration` is needed, otherwise
 * `LdapInjectionCustomizations` should be imported instead.
 */

import python
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
// import LdapInjectionCustomizations::LdapInjection
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/LdapInjectionCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "ldap injection"
 * vulnerabilities, as well as extension points for adding your own.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "ldap injection"
 * vulnerabilities, as well as extension points for adding your own.
 */
module LdapInjection {
  /**
   * A data flow source for "ldap injection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "ldap injection" vulnerabilities.
   */
  abstract class DnSink extends DataFlow::Node { }

  /**
   * A data flow sink for "ldap injection" vulnerabilities.
   */
  abstract class FilterSink extends DataFlow::Node { }

  /**
   * A sanitizer for "ldap injection" vulnerabilities.
   */
  abstract class DnSanitizer extends DataFlow::Node { }

  /**
   * A sanitizer for "ldap injection" vulnerabilities.
   */
  abstract class FilterSanitizer extends DataFlow::Node { }

  /**
   * DEPRECATED: Use `ActiveThreatModelSource` from Concepts instead!
   */
  deprecated class RemoteFlowSourceAsSource = ActiveThreatModelSourceAsSource;

  /**
   * An active threat-model source, considered as a flow source.
   */
  private class ActiveThreatModelSourceAsSource extends Source, ActiveThreatModelSource { }

  /**
   * A logging operation, considered as a flow sink.
   */
  class LdapExecutionAsDnSink extends DnSink {
    LdapExecutionAsDnSink() { this = any(Ldap::LdapExecution ldap).getBaseDn() }
  }

  /**
   * A logging operation, considered as a flow sink.
   */
  class LdapExecutionAsFilterSink extends FilterSink {
    LdapExecutionAsFilterSink() { this = any(Ldap::LdapExecution ldap).getFilter() }
  }

  /**
   * A comparison with a constant, considered as a sanitizer-guard.
   */
  class ConstCompareAsDnSanitizerGuard extends DnSanitizer, ConstCompareBarrier { }

  /** DEPRECATED: Use ConstCompareAsDnSanitizerGuard instead. */
  deprecated class StringConstCompareAsSanitizerGuard = ConstCompareAsDnSanitizerGuard;

  /**
   * A comparison with a constant, considered as a sanitizer-guard.
   */
  class ConstCompareAsFilterSanitizerGuard extends FilterSanitizer, ConstCompareBarrier { }

  /** DEPRECATED: Use ConstCompareAsFilterSanitizerGuard instead. */
  deprecated class StringConstCompareAsFilterSanitizerGuard = ConstCompareAsFilterSanitizerGuard;

  /**
   * A call to replace line breaks functions as a sanitizer.
   */
  class LdapDnEscapingSanitizer extends DnSanitizer, DataFlow::CallCfgNode {
    LdapDnEscapingSanitizer() { this = any(LdapDnEscaping ldapDnEsc).getOutput() }
  }

  /**
   * A call to replace line breaks functions as a sanitizer.
   */
  class LdapFilterEscapingSanitizer extends FilterSanitizer, DataFlow::CallCfgNode {
    LdapFilterEscapingSanitizer() { this = any(LdapFilterEscaping ldapDnEsc).getOutput() }
  }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/LdapInjectionCustomizations.qll ---

private module LdapInjectionDnConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof DnSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof DnSanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "LDAP injection via the distinguished name (DN) parameter" vulnerabilities. */
module LdapInjectionDnFlow = TaintTracking::Global<LdapInjectionDnConfig>;

private module LdapInjectionFilterConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof FilterSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof FilterSanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "LDAP injection via the filter parameter" vulnerabilities. */
module LdapInjectionFilterFlow = TaintTracking::Global<LdapInjectionFilterConfig>;

/** Global taint-tracking for detecting "LDAP injection" vulnerabilities. */
module LdapInjectionFlow =
  DataFlow::MergePathGraph<LdapInjectionDnFlow::PathNode, LdapInjectionFilterFlow::PathNode,
    LdapInjectionDnFlow::PathGraph, LdapInjectionFilterFlow::PathGraph>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/LdapInjectionQuery.qll ---
// import LdapInjectionFlow::PathGraph

from LdapInjectionFlow::PathNode source, LdapInjectionFlow::PathNode sink, string parameterName
where
  LdapInjectionDnFlow::flowPath(source.asPathNode1(), sink.asPathNode1()) and
  parameterName = "DN"
  or
  LdapInjectionFilterFlow::flowPath(source.asPathNode2(), sink.asPathNode2()) and
  parameterName = "filter"
select sink.getNode(), source, sink,
  "LDAP query parameter (" + parameterName + ") depends on a $@.", source.getNode(),
  "user-provided value"
