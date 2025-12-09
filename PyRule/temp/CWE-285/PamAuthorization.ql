/**
 * @name PAM authorization bypass due to incorrect usage
 * @description Not using `pam_acct_mgmt` after `pam_authenticate` to check the validity of a login can lead to authorization bypass.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.1
 * @precision high
 * @id py/pam-auth-bypass
 * @tags security
 *       external/cwe/cwe-285
 */

import python
// import PamAuthorizationFlow::PathGraph
import semmle.python.ApiGraphs
// import semmle.python.security.dataflow.PamAuthorizationQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/PamAuthorizationQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting "PAM Authorization" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `PamAuthorization::Configuration` is needed, otherwise
 * `PamAuthorizationCustomizations` should be imported instead.
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.TaintTracking
// import PamAuthorizationCustomizations::PamAuthorizationCustomizations
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/PamAuthorizationCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "PAM Authorization" vulnerabilities.
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.Concepts

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "PAM Authorization" vulnerabilities.
 */
module PamAuthorizationCustomizations {
  /**
   * Models a node corresponding to the `pam` library
   */
  API::Node libPam() {
    exists(API::CallNode findLibCall, API::CallNode cdllCall |
      findLibCall =
        API::moduleImport("ctypes").getMember("util").getMember("find_library").getACall() and
      findLibCall.getParameter(0).getAValueReachingSink().asExpr().(StringLiteral).getText() = "pam" and
      cdllCall = API::moduleImport("ctypes").getMember("CDLL").getACall() and
      cdllCall.getParameter(0).getAValueReachingSink() = findLibCall
    |
      result = cdllCall.getReturn()
    )
  }

  /**
   * A data flow source for "PAM Authorization" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "PAM Authorization" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * DEPRECATED: Use `ActiveThreatModelSource` from Concepts instead!
   */
  deprecated class RemoteFlowSourceAsSource = ActiveThreatModelSourceAsSource;

  /**
   * An active threat-model source, considered as a flow source.
   */
  private class ActiveThreatModelSourceAsSource extends Source, ActiveThreatModelSource { }

  /**
   * A vulnerable `pam_authenticate` call considered as a flow sink.
   */
  class VulnPamAuthCall extends API::CallNode, Sink {
    VulnPamAuthCall() {
      exists(DataFlow::Node h |
        this = libPam().getMember("pam_authenticate").getACall() and
        h = this.getArg(0) and
        not exists(API::CallNode acctMgmtCall |
          acctMgmtCall = libPam().getMember("pam_acct_mgmt").getACall() and
          DataFlow::localFlow(h, acctMgmtCall.getArg(0))
        )
      )
    }
  }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/PamAuthorizationCustomizations.qll ---

private module PamAuthorizationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Models flow from a remotely supplied username field to a PAM `handle`.
    // `retval = pam_start(service, username, byref(conv), byref(handle))`
    exists(API::CallNode pamStart, DataFlow::Node handle, API::CallNode pointer |
      pointer = API::moduleImport("ctypes").getMember(["pointer", "byref"]).getACall() and
      pamStart = libPam().getMember("pam_start").getACall() and
      pointer = pamStart.getArg(3) and
      handle = pointer.getArg(0) and
      pamStart.getArg(1) = node1 and
      handle = node2
    )
    or
    // Flow from handle to the authenticate call in the final step
    exists(VulnPamAuthCall c | c.getArg(0) = node1 | node2 = c)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "PAM Authorization" vulnerabilities. */
module PamAuthorizationFlow = TaintTracking::Global<PamAuthorizationConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/PamAuthorizationQuery.qll ---

from PamAuthorizationFlow::PathNode source, PamAuthorizationFlow::PathNode sink
where PamAuthorizationFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This PAM authentication depends on a $@, and 'pam_acct_mgmt' is not called afterwards.",
  source.getNode(), "user-provided value"
