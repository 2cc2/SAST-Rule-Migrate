/**
 * @name Dangerous Interactive Code Run Audit
 * @description Found dynamic content inside InteractiveConsole/InteractiveInterpreter method. This is dangerous if external data can reach this function call because it allows a malicious actor to run arbitrary Python code. Ensure no external data reaches here.
 * @kind taint
 * @problem.severity warning
 * @id python/dangerous-interactive-code-run-audit
 * @tags security
 *       python
 *       external/cwe/cwe-95
 *       external/owasp/a03
 */

import python
import semmle.python.dataflow.TaintTracking
import semmle.python.ApiGraphs

class DangerousSource extends DataFlow::Node {
  DangerousSource() {
    exists(
      CallNode call |
      call.getMethodName() in ["push", "runsource", "runcode"] and
      call.getTarget().getType().getClassName() in ["InteractiveConsole", "InteractiveInterpreter"] and
      this.asExpr() = call.getArg(0) and
      not call.getArg(0).getStringValue() = "\"\"...\"\""
    )
    or
    exists(
      CallNode call |
      call.getScope().toString() = "code" and
      call.getMethodName() = "compile_command" and
      this.asExpr() = call.getArg(0)
    )
  }
}

class SafeLiteral extends DataFlow::Node {
  SafeLiteral() {
    exists(CallNode call | this.asExpr() = call.getArg(0) and call.getArg(0).getStringValue() = "\"\"...\"\"")
  }
}

class CodeExecutionSink extends DataFlow::Node {
  CodeExecutionSink() {
    exists(
      CallNode call |
      call.getMethodName() in ["push", "runsource", "runcode"] and
      call.getTarget().getType().getClassName() in ["InteractiveConsole", "InteractiveInterpreter"] and
      this.asExpr() = call.getArg(0)
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "DangerousInteractiveCodeRunAudit" }

  override predicate isSource(DataFlow::Node source) { source instanceof DangerousSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof CodeExecutionSink }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof SafeLiteral }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(CallNode srcCall, CallNode sinkCall |
      pred.asExpr() = srcCall.getArg(0) and
      succ.asExpr() = sinkCall.getArg(0) and
      srcCall.getMethodName() = "compile_command" and
      sinkCall.getMethodName() = "runcode"
    )
  }
}

from Config cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Found dynamic content inside InteractiveConsole/InteractiveInterpreter method. " +
  "This is dangerous if external data can reach this function call because it " +
  "allows a malicious actor to run arbitrary Python code. Ensure no external data reaches here."