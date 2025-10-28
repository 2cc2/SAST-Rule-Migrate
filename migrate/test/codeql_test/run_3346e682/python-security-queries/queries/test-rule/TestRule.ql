/**
 * @name Dangerous Interactive Code Execution
 * @description Detects dynamic content inside InteractiveConsole/InteractiveInterpreter methods
 * @kind path-problem
 * @problem.severity warning
 * @id python/dangerous-interactive-code-run-audit
 */

import python
import semmle.python.security.TaintTracking
import DataFlow::PathGraph

class DangerousInput extends DataFlow::Node {
  DangerousInput() {
    exists(string s | s = this.asExpr().(StringLiteral).getText() | s != "\"...\"")
  }
}

class InteractiveCodeExecution extends DataFlow::Node {
  InteractiveCodeExecution() {
    exists(Call call |
      call = this.asExpr() |
      call.getTarget().(Attribute).getName() in ["push", "runsource", "runcode"] and
      call.getTarget().(Attribute).getObject().(Class).getName() in ["InteractiveConsole", "InteractiveInterpreter"]
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "DangerousInteractiveCodeRun" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof DangerousInput
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof InteractiveCodeExecution
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(string s | s = node.asExpr().(StringLiteral).getText() | s == "\"...\"")
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Found dynamic content inside InteractiveConsole/InteractiveInterpreter method.", 
  source, "User-controlled input",
  sink, "Potentially dangerous code execution"