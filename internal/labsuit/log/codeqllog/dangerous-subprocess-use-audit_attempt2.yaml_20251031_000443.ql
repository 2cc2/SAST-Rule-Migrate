/**
 * @name Dangerous subprocess use
 * @description Detected subprocess function call without a static string.
 *              If this data can be controlled by a malicious actor, it may be
 *              an instance of command injection.
 * @kind path-problem
 * @problem.severity error
 * @id py/dangerous-subprocess-use
 * @tags security
 *       external/cwe/cwe-078
 *       owasp-a01:2017/injection
 *       owasp-a03:2021/injection
 */
import python
import semmle.python.dataflow.DataFlow
import semmle.python.ApiGraphs
import semmle.python.Concepts

private class SubprocessSource extends DataFlow::Node::Range {
  SubprocessSource() {
    exists(Call call |
      call.getFunc().(Name).getId() = "subprocess" and
      this.asExpr() = call.getArgument(0).getValue()
    )
  }
}

private class CommandSink extends DataFlow::Node::Range {
  CommandSink() {
    exists(Call call, string funcName |
      call.getFunc().(Name).getId() = "subprocess" and
      funcName = call.getFunc().(Name).getId() and
      funcName.matches(".*") and
      this.asExpr() = call.getArgument(.getExpr()
    )
  }
}

private class SafeSubprocessUse extends DataFlow::Node::Range {
  SafeSubprocessUse() {
    exists(Call call |
      call.getFunc().(Name).getId() = "subprocess" and
      this.asExpr() = call.getArgument(0).getValue()
    )
  }
}

private class SubprocessTaintConfig extends TaintTracking::Configuration {
  SubprocessTaintConfig() { this = "SubprocessTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SubprocessSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(string shellPattern |
      shellPattern = sink.getExpr().toString() and
      shellPattern.matches("^(sh|bash|ksh|csh|tcsh|zsh|python)")
    ) and
    sink instanceof CommandSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SafeSubprocessUse
  }
}

from SubprocessTaintConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlowPath(source, sink)
select sink, "Detected subprocess function call without a static string. " +
  "If this data can be controlled by a malicious actor, it may be an " +
  "instance of command injection. Audit the use of this call to ensure it " +
  "is not controllable by an external resource. You may consider using 'shlex.escape()'."