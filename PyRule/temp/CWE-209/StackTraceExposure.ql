/**
 * @name Information exposure through an exception
 * @description Leaking information about an exception, such as messages and stack traces, to an
 *              external user can expose implementation details that are useful to an attacker for
 *              developing a subsequent exploit.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 5.4
 * @precision high
 * @id py/stack-trace-exposure
 * @tags security
 *       external/cwe/cwe-209
 *       external/cwe/cwe-497
 */

import python
// import semmle.python.security.dataflow.StackTraceExposureQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/StackTraceExposureQuery.qll ---
/**
 * Provides a taint-tracking configuration for detecting "stack trace exposure" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `StackTraceExposure::Configuration` is needed, otherwise
 * `StackTraceExposureCustomizations` should be imported instead.
 */

private import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// import StackTraceExposureCustomizations::StackTraceExposure
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/StackTraceExposureCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "stack trace exposure"
 * vulnerabilities, as well as extension points for adding your own.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.BarrierGuards
// private import ExceptionInfo
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/ExceptionInfo.qll ---
/** Provides classes representing various sources of information about raised exceptions. */

import python
import semmle.python.dataflow.new.DataFlow
private import semmle.python.ApiGraphs

/**
 * INTERNAL: Do not use.
 *
 * A data-flow node that carries information about a raised exception.
 * Such information should rarely be exposed directly to the user.
 */
abstract class ExceptionInfo extends DataFlow::Node { }

/** A call to a function from the `traceback` module revealing information about a raised exception. */
private class TracebackFunctionCall extends ExceptionInfo, DataFlow::CallCfgNode {
  TracebackFunctionCall() {
    this =
      API::moduleImport("traceback")
          .getMember([
              "extract_tb", "extract_stack", "format_list", "format_exception_only",
              "format_exception", "format_exc", "format_tb", "format_stack"
            ])
          .getACall()
  }
}

/** A caught exception. */
private class CaughtException extends ExceptionInfo {
  CaughtException() {
    this.asExpr() = any(ExceptStmt s).getName() and
    this.asCfgNode() = any(EssaNodeDefinition def).getDefiningNode()
  }
}

/** A call to `sys.exc_info`. */
private class SysExcInfoCall extends ExceptionInfo, DataFlow::CallCfgNode {
  SysExcInfoCall() { this = API::moduleImport("sys").getMember("exc_info").getACall() }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/ExceptionInfo.qll ---

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "stack trace exposure"
 * vulnerabilities, as well as extension points for adding your own.
 */
module StackTraceExposure {
  /**
   * A data flow source for "stack trace exposure" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "stack trace exposure" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "stack trace exposure" vulnerabilities.
   */
  abstract class Sanitizer extends DataFlow::Node { }

  /**
   * A source of exception info, considered as a flow source.
   */
  class ExceptionInfoAsSource extends Source instanceof ExceptionInfo {
    ExceptionInfoAsSource() {
      // since `traceback.format_exc()` in Python 2 is internally implemented as
      // ```py
      // def format_exc(limit=None):
      //     """Like print_exc() but return a string."""
      //     try:
      //         etype, value, tb = sys.exc_info()
      //         return ''.join(format_exception(etype, value, tb, limit))
      //     finally:
      //         etype = value = tb = None
      // ```
      // any time we would report flow to such from a call to format_exc, we can ALSO report
      // the flow from the `sys.exc_info()` source -- obviously we don't want that.
      //
      //
      // To avoid this, we use the same approach as for sinks in the command injection
      // query (and others).
      not exists(Module traceback |
        traceback.getName() = "traceback" and
        this.getScope().getEnclosingModule() = traceback and
        // do allow this call if we're analyzing traceback.py as part of CPython though
        not exists(traceback.getFile().getRelativePath())
      )
    }
  }

  /**
   * The body of a HTTP response that will be returned from a server, considered as a flow sink.
   */
  class ServerHttpResponseBodyAsSink extends Sink {
    ServerHttpResponseBodyAsSink() { this = any(Http::Server::HttpResponse response).getBody() }
  }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/StackTraceExposureCustomizations.qll ---

private module StackTraceExposureConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

  // A stack trace is accessible as the `__traceback__` attribute of a caught exception.
  //  see https://docs.python.org/3/reference/datamodel.html#traceback-objects
  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(DataFlow::AttrRead attr | attr.getAttributeName() = "__traceback__" |
      nodeFrom = attr.getObject() and
      nodeTo = attr
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "stack trace exposure" vulnerabilities. */
module StackTraceExposureFlow = TaintTracking::Global<StackTraceExposureConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/StackTraceExposureQuery.qll ---
// import StackTraceExposureFlow::PathGraph

from StackTraceExposureFlow::PathNode source, StackTraceExposureFlow::PathNode sink
where StackTraceExposureFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "$@ flows to this location and may be exposed to an external user.", source.getNode(),
  "Stack trace information"
