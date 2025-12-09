/**
 * @name Uncontrolled command line
 * @description Using externally controlled strings in a command line may allow a malicious
 *              user to change the meaning of the command.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @sub-severity high
 * @precision high
 * @id py/command-line-injection
 * @tags correctness
 *       security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import python

// import CommandInjectionFlow::PathGraph


import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards
private import semmle.python.frameworks.data.ModelsAsData

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "command injection"
 * vulnerabilities, as well as extension points for adding your own.
 */
module CommandInjection {
  /**
   * A data flow source for "command injection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "command injection" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "command injection" vulnerabilities.
   */
  abstract class Sanitizer extends DataFlow::Node { }

  /**
   * An active threat-model source, considered as a flow source.
   */
  private class ActiveThreatModelSourceAsSource extends Source, ActiveThreatModelSource { }

  /**
   * A command execution, considered as a flow sink.
   */
  class CommandExecutionAsSink extends Sink {
    CommandExecutionAsSink() {
      this = any(SystemCommandExecution e).getCommand() and
      not this.getScope().getEnclosingModule().getName() in [
          "os", "subprocess", "platform", "popen2"
        ]
    }
  }

  private class SinkFromModel extends Sink {
    SinkFromModel() { this = ModelOutput::getASinkNode("command-injection").asSink() }
  }

  /**
   * A comparison with a constant, considered as a sanitizer-guard.
   */
  class ConstCompareAsSanitizerGuard extends Sanitizer, ConstCompareBarrier { }
}

/**
 * A taint-tracking configuration for detecting "command injection" vulnerabilities.
 */
module CommandInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof CommandInjection::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof CommandInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof CommandInjection::Sanitizer }
  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Global taint-tracking for detecting "command injection" vulnerabilities. */
module CommandInjectionFlow = TaintTracking::Global<CommandInjectionConfig>;

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This command line depends on a $@.", source.getNode(),
  "user-provided value"
