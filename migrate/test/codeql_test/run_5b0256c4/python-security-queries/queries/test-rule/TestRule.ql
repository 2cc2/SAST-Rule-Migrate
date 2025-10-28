/**
 * @name Dangerous interactive code run
 * @description Dynamic content inside InteractiveConsole/InteractiveInterpreter method detected.
 *              This is dangerous if external data can reach this function call because it allows
 *              a malicious actor to run arbitrary Python code.
 * @kind taint
 * @problem.severity warning
 * @id py/dangerous-interactive-code-run
 */

import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import DataFlow::PathGraph

class DynamicCodeInput extends DataFlow::Node {
  DynamicCodeInput() {
    exists(DataFlow::CallNode call |
      call.getAPIName().regexpMatch(".*\\.(push|runsource|runcode|compile_command)") and
      // Exclude string literals that are safely quoted
      not this.asExpr() instanceof StringLiteral and
      this = call.getArgument(0)
    )
  }
}

class CodeExecutionSink extends DataFlow::Node {
  CodeExecutionSink() {
    exists(API::Call call |
      call.getReceiverType().(
        getName() = "InteractiveConsole" or getName() = "InteractiveInterpreter"
      ) and
      call.getAPIName() in ["push", "runsource", "runcode"]
    )
  }
}

class DangerousInteractiveRunConfig extends TaintTracking::Configuration {
  DangerousInteractiveRunConfig() { this = "DangerousInteractiveRunConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof DynamicCodeInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof CodeExecutionSink }

  // Exclude safe string literals from taint flow
  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() instanceof StringLiteral
  }
}

from DangerousInteractiveRunConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Found dynamic content inside InteractiveConsole/InteractiveInterpreter method. " +
       "This is dangerous if external data can reach this function call because it allows " +
       "a malicious actor to run arbitrary Python code. Ensure no external data reaches here."