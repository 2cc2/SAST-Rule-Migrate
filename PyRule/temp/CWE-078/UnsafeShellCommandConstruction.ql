/**
 * @name Unsafe shell command constructed from library input
 * @description Using externally controlled strings in a command line may allow a malicious
 *              user to change the meaning of the command.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.3
 * @precision medium
 * @id py/shell-command-constructed-from-input
 * @tags correctness
 *       security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 *       external/cwe/cwe-073
 */

import python
// import semmle.python.security.dataflow.UnsafeShellCommandConstructionQuery
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/UnsafeShellCommandConstructionQuery.qll ---
/**
 * Provides a taint tracking configuration for reasoning about shell command
 * constructed from library input vulnerabilities
 *
 * Note, for performance reasons: only import this file if `Configuration` is needed,
 * otherwise `UnsafeShellCommandConstructionCustomizations` should be imported instead.
 */

import python
import semmle.python.dataflow.new.DataFlow
// import UnsafeShellCommandConstructionCustomizations::UnsafeShellCommandConstruction
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/UnsafeShellCommandConstructionCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for reasoning about
 * shell command constructed from library input vulnerabilities, as
 * well as extension points for adding your own.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
// private import CommandInjectionCustomizations::CommandInjection as CommandInjection
// --- begin inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/CommandInjectionCustomizations.qll ---
/**
 * Provides default sources, sinks and sanitizers for detecting
 * "command injection"
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
   * DEPRECATED: Use `ActiveThreatModelSource` from Concepts instead!
   */
  deprecated class RemoteFlowSourceAsSource = ActiveThreatModelSourceAsSource;

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
      // Since the implementation of standard library functions such `os.popen` looks like
      // ```py
      // def popen(cmd, mode="r", buffering=-1):
      //     ...
      //     proc = subprocess.Popen(cmd, ...)
      // ```
      // any time we would report flow to the `os.popen` sink, we can ALSO report the flow
      // from the `cmd` parameter to the `subprocess.Popen` sink -- obviously we don't
      // want that.
      //
      // However, simply removing taint edges out of a sink is not a good enough solution,
      // since we would only flag one of the `os.system` calls in the following example
      // due to use-use flow
      // ```py
      // os.system(cmd)
      // os.system(cmd)
      // ```
      //
      // Best solution I could come up with is to exclude all sinks inside the modules of
      // known sinks. This does have a downside: If we have overlooked a function in any
      // of these, that internally runs a command, we no longer give an alert :| -- and we
      // need to keep them updated (which is hard to remember)
      //
      // This does not only affect `os.popen`, but also the helper functions in
      // `subprocess`. See:
      // https://github.com/python/cpython/blob/fa7ce080175f65d678a7d5756c94f82887fc9803/Lib/os.py#L974
      // https://github.com/python/cpython/blob/fa7ce080175f65d678a7d5756c94f82887fc9803/Lib/subprocess.py#L341
      //
      // The same approach is used in the path-injection, cleartext-storage, and
      // cleartext-logging queries.
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

  /** DEPRECATED: Use ConstCompareAsSanitizerGuard instead. */
  deprecated class StringConstCompareAsSanitizerGuard = ConstCompareAsSanitizerGuard;
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/CommandInjectionCustomizations.qll ---
private import semmle.python.Concepts as Concepts
private import semmle.python.ApiGraphs

/**
 * Module containing sources, sinks, and sanitizers for shell command constructed from library input.
 */
module UnsafeShellCommandConstruction {
  /** A source for shell command constructed from library input vulnerabilities. */
  abstract class Source extends DataFlow::Node { }

  /** A sanitizer for shell command constructed from library input vulnerabilities. */
  abstract class Sanitizer extends DataFlow::Node { }

  private import semmle.python.frameworks.Setuptools

  /** An input parameter to a gem seen as a source. */
  private class LibraryInputAsSource extends Source instanceof DataFlow::ParameterNode {
    LibraryInputAsSource() {
      this = Setuptools::getALibraryInput() and
      not this.getParameter().getName().matches(["cmd%", "command%", "%_command", "%_cmd"])
    }
  }

  /** A sink for shell command constructed from library input vulnerabilities. */
  abstract class Sink extends DataFlow::Node {
    Sink() { not this.asExpr() instanceof StringLiteral } // filter out string constants, makes testing easier

    /** Gets a description of how the string in this sink was constructed. */
    abstract string describe();

    /** Gets the dataflow node where the string is constructed. */
    DataFlow::Node getStringConstruction() { result = this }

    /** Gets the dataflow node that executed the string as a shell command. */
    abstract DataFlow::Node getCommandExecution();
  }

  /** Holds if the string constructed at `source` is executed at `shellExec` */
  predicate isUsedAsShellCommand(DataFlow::Node source, Concepts::SystemCommandExecution shellExec) {
    source = backtrackShellExec(TypeTracker::TypeBackTracker::end(), shellExec)
  }

  import semmle.python.dataflow.new.TypeTracking as TypeTracker

  private DataFlow::LocalSourceNode backtrackShellExec(
    TypeTracker::TypeBackTracker t, Concepts::SystemCommandExecution shellExec
  ) {
    t.start() and
    result = any(DataFlow::Node n | shellExec.isShellInterpreted(n)).getALocalSource()
    or
    exists(TypeTracker::TypeBackTracker t2 |
      result = backtrackShellExec(t2, shellExec).backtrack(t2, t)
    )
  }

  /**
   * A string constructed from a string-literal (e.g. `f'foo {sink}'`),
   * where the resulting string ends up being executed as a shell command.
   */
  class StringInterpolationAsSink extends Sink {
    Concepts::SystemCommandExecution s;
    Fstring fstring;

    StringInterpolationAsSink() {
      isUsedAsShellCommand(DataFlow::exprNode(fstring), s) and
      this.asExpr() = fstring.getASubExpression()
    }

    override string describe() { result = "f-string" }

    override DataFlow::Node getCommandExecution() { result = s }

    override DataFlow::Node getStringConstruction() { result.asExpr() = fstring }
  }

  /**
   * A component of a string-concatenation (e.g. `"foo " + sink`),
   * where the resulting string ends up being executed as a shell command.
   */
  class StringConcatAsSink extends Sink {
    Concepts::SystemCommandExecution s;
    BinaryExpr add;

    StringConcatAsSink() {
      add.getOp() instanceof Add and
      isUsedAsShellCommand(any(DataFlow::Node n | n.asExpr() = add), s) and
      this.asExpr() = add.getASubExpression()
    }

    override DataFlow::Node getCommandExecution() { result = s }

    override string describe() { result = "string concatenation" }

    override DataFlow::Node getStringConstruction() { result.asExpr() = add }
  }

  /**
   * A string constructed using a `" ".join(...)` call, where the resulting string ends up being executed as a shell command.
   */
  class ArrayJoin extends Sink {
    Concepts::SystemCommandExecution s;
    DataFlow::MethodCallNode call;

    ArrayJoin() {
      call.getMethodName() = "join" and
      unique( | | call.getArg(_)).asExpr().(StringLiteral).getText() = " " and
      isUsedAsShellCommand(call, s) and
      (
        this = call.getArg(0) and
        not call.getArg(0).asExpr() instanceof List
        or
        this.asExpr() = call.getArg(0).asExpr().(List).getASubExpression()
      )
    }

    override string describe() { result = "array" }

    override DataFlow::Node getCommandExecution() { result = s }

    override DataFlow::Node getStringConstruction() { result = call }
  }

  /**
   * A string constructed from a format call,
   * where the resulting string ends up being executed as a shell command.
   * Either a call to `.format(..)` or a string-interpolation with a `%` operator.
   */
  class TaintedFormatStringAsSink extends Sink {
    Concepts::SystemCommandExecution s;
    DataFlow::Node formatCall;

    TaintedFormatStringAsSink() {
      (
        formatCall.asExpr().(BinaryExpr).getOp() instanceof Mod and
        this.asExpr() = formatCall.asExpr().(BinaryExpr).getASubExpression()
        or
        formatCall.(DataFlow::MethodCallNode).getMethodName() = "format" and
        this =
          [
            formatCall.(DataFlow::MethodCallNode).getArg(_),
            formatCall.(DataFlow::MethodCallNode).getObject()
          ]
      ) and
      isUsedAsShellCommand(formatCall, s)
    }

    override string describe() { result = "formatted string" }

    override DataFlow::Node getCommandExecution() { result = s }

    override DataFlow::Node getStringConstruction() { result = formatCall }
  }

  /**
   * A call to `shlex.quote`, considered as a sanitizer.
   */
  class ShlexQuoteAsSanitizer extends Sanitizer, DataFlow::Node {
    ShlexQuoteAsSanitizer() {
      this = API::moduleImport("shlex").getMember("quote").getACall().getArg(0)
    }
  }
}
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/UnsafeShellCommandConstructionCustomizations.qll ---
private import semmle.python.dataflow.new.TaintTracking
// private import CommandInjectionCustomizations::CommandInjection as CommandInjection
private import semmle.python.dataflow.new.BarrierGuards

/**
 * A taint-tracking configuration for detecting "shell command constructed from library input" vulnerabilities.
 */
module UnsafeShellCommandConstructionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof Sanitizer or
    node instanceof CommandInjection::Sanitizer // using all sanitizers from `py/command-injection`
  }

  // override to require the path doesn't have unmatched return steps
  DataFlow::FlowFeature getAFeature() { result instanceof DataFlow::FeatureHasSourceCallContext }

  predicate observeDiffInformedIncrementalMode() { any() }

  Location getASelectedSinkLocation(DataFlow::Node sink) {
    result = sink.(Sink).getLocation()
    or
    result = sink.(Sink).getStringConstruction().getLocation()
    or
    result = sink.(Sink).getCommandExecution().getLocation()
  }
}

/** Global taint-tracking for detecting "shell command constructed from library input" vulnerabilities. */
module UnsafeShellCommandConstructionFlow =
  TaintTracking::Global<UnsafeShellCommandConstructionConfig>;
// --- end inlined: ../CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow/UnsafeShellCommandConstructionQuery.qll ---
// import UnsafeShellCommandConstructionFlow::PathGraph

from
  UnsafeShellCommandConstructionFlow::PathNode source,
  UnsafeShellCommandConstructionFlow::PathNode sink, Sink sinkNode
where
  UnsafeShellCommandConstructionFlow::flowPath(source, sink) and
  sinkNode = sink.getNode()
select sinkNode.getStringConstruction(), source, sink,
  "This " + sinkNode.describe() + " which depends on $@ is later used in a $@.", source.getNode(),
  "library input", sinkNode.getCommandExecution(), "shell command"
