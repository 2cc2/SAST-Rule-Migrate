/**
 * @name Dangerous interactive code execution
 * @description Found dynamic content inside InteractiveConsole/InteractiveInterpreter method. This is dangerous if external data can reach this function call because it allows a malicious actor to run arbitrary Python code.
 * @kind path-problem
 * @id python/dangerous-interactive-code-run
 * @problem.severity warning
 * @security-severity 7.8
 * @tags security
 *       external/cwe/cwe-095
 *       external/owasp/a03
 */

import python
import DataFlow::PathGraph
import semmle.python.ApiGraphs

class DangerousSource extends DataFlow::Node {
  DangerousSource() {
    exists(CallNode call |
      call.getFunc().getQualifiedName() in [
        "code.InteractiveConsole.push",
        "code.InteractiveConsole.runsource",
        "code.InteractiveConsole.runcode",
        "code.InteractiveInterpreter.push",
        "code.InteractiveInterpreter.runsource",
        "code.InteractiveInterpreter.runcode"
      ] and
      not call.getArgument(0).getStringValue().regexpMatch("^\"\\.\\.\\.\"$")
    ) and
    this.asExpr() = call.getArgument(0)

    or

    exists(CallNode call |
      call.getFunc().getQualifiedName() = "code.compile_command" and
      this.asExpr() = call.getArgument(0)
    )
  }
}

class SafeLiteral extends DataFlow::Node {
  SafeLiteral() {
    exists(CallNode call |
      call.getFunc().getQualifiedName() in [
        "code.InteractiveConsole.push",
        "code.InteractiveConsole.runsource",
        "code.InteractiveConsole.runcode",
        "code.InteractiveInterpreter.push",
        "code.InteractiveInterpreter.runsource",
        "code.InteractiveInterpreter.runcode"
      ] and
      call.getArgument(0).getStringValue().regexpMatch("^\"\\.\\.\\.\"$") and
      this.asExpr() = call.getArgument(0)
    )
  }
}

class CodeExecutionSink extends DataFlow::Node {
  CodeExecutionSink() {
    exists(CallNode call |
      call.getFunc().getQualifiedName() in [
        "code.InteractiveConsole.push",
        "code.InteractiveConsole.runsource",
        "code.InteractiveConsole.runcode",
        "code.InteractiveInterpreter.push",
        "code.InteractiveInterpreter.runsource",
        "code.InteractiveInterpreter.runcode"
      ] and
      this.asExpr() = call.getArgument(0)
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "Dynamic code execution configuration" }

  override predicate isSource(DataFlow::Node source) { source instanceof DangerousSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof CodeExecutionSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) { sanitizer instanceof SafeLiteral }

  override predicate isAdditionalTaintStep(DataFlow::Node src, DataFlow::Node sink) {
    exists(Function f, Parameter p |
      src.asParameter() = p and
      sink.asExpr() = f.getACall().getArgument(p.getIndex()) and
      f.getACall().getFunc().getQualifiedName() = "code.compile_command" and
      sink.getEnclosingCallable().getQualifiedName() = "code.InteractiveInterpreter.runcode"
    )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Found dynamic content inside InteractiveConsole/InteractiveInterpreter method. $" +
  "This is dangerous if external data can reach this function call because it allows a " +
  "malicious actor to run arbitrary Python code. Ensure no external data reaches here.",
  source, source.getNode().getEnclosingCallable()