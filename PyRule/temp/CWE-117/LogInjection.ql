/**
 * @name Log Injection
 * @description Building log entries from user-controlled data is vulnerable to
 *              insertion of forged log entries by a malicious user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision medium
 * @id py/log-injection
 * @tags security
 *       external/cwe/cwe-117
 */

import python
// import semmle.python.security.dataflow.LogInjectionQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/LogInjectionQuery.qll ---
/**
 * Provides a taint-tracking configuration for tracking "log injection" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `LogInjection::Configuration` is needed, otherwise
 * `LogInjectionCustomizations` should be imported instead.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
// import LogInjectionCustomizations::LogInjection
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/LogInjectionCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "log injection"
 * vulnerabilities, as well as extension points for adding your own.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards
private import semmle.python.frameworks.data.ModelsAsData

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "log injection"
 * vulnerabilities, as well as extension points for adding your own.
 */
module LogInjection {
  /**
   * A data flow source for "log injection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "log injection" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "log injection" vulnerabilities.
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
   * A logging operation, considered as a flow sink.
   */
  class LoggingAsSink extends Sink {
    LoggingAsSink() {
      this = any(Logging write).getAnInput() and
      // since the inner implementation of the `logging.Logger.warn` function is
      // ```py
      // class Logger:
      //     def warn(self, msg, *args, **kwargs):
      //         warnings.warn("The 'warn' method is deprecated, "
      //             "use 'warning' instead", DeprecationWarning, 2)
      //         self.warning(msg, *args, **kwargs)
      // ```
      // any time we would report flow to such a logging sink, we can ALSO report
      // the flow to the `self.warning` sink -- obviously we don't want that.
      //
      // However, simply removing taint edges out of a sink is not a good enough solution,
      // since we would only flag one of the `logging.info` calls in the following example
      // due to use-use flow
      // ```py
      // logger.warn(user_controlled)
      // logger.warn(user_controlled)
      // ```
      //
      // The same approach is used in the command injection query.
      not exists(Module loggingInit |
        loggingInit.getName() = "logging.__init__" and
        this.getScope().getEnclosingModule() = loggingInit and
        // do allow this call if we're analyzing logging/__init__.py as part of CPython though
        not exists(loggingInit.getFile().getRelativePath())
      )
    }
  }

  private class SinkFromModel extends Sink {
    SinkFromModel() { this = ModelOutput::getASinkNode("log-injection").asSink() }
  }

  /**
   * A comparison with a constant, considered as a sanitizer-guard.
   */
  class ConstCompareAsSanitizerGuard extends Sanitizer, ConstCompareBarrier { }

  /** DEPRECATED: Use ConstCompareAsSanitizerGuard instead. */
  deprecated class StringConstCompareAsSanitizerGuard = ConstCompareAsSanitizerGuard;

  /**
   * A call to replace line breaks, considered as a sanitizer.
   */
  class ReplaceLineBreaksSanitizer extends Sanitizer, DataFlow::CallCfgNode {
    // Note: This sanitizer is not 100% accurate, since:
    // - we do not check that all kinds of line breaks are replaced
    // - we do not check that one kind of line breaks is not replaced by another
    //
    // However, we lack a simple way to do better, and the query would likely
    // be too noisy without this.
    //
    // TODO: Consider rewriting using flow states.
    ReplaceLineBreaksSanitizer() {
      this.getFunction().(DataFlow::AttrRead).getAttributeName() = "replace" and
      this.getArg(0).asExpr().(StringLiteral).getText() in ["\r\n", "\n"]
    }
  }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/LogInjectionCustomizations.qll ---

private module LogInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "log injection" vulnerabilities. */
module LogInjectionFlow = TaintTracking::Global<LogInjectionConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/LogInjectionQuery.qll ---
// import LogInjectionFlow::PathGraph

from LogInjectionFlow::PathNode source, LogInjectionFlow::PathNode sink
where LogInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This log entry depends on a $@.", source.getNode(),
  "user-provided value"
