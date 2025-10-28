/**
 * @name Dangerous subprocess usage
 * @description Detects subprocess functions without static string arguments that could lead to command injection
 * @kind taint
 * @severity Error
 * @id py/dangerous-subprocess-use-audit
 */

import python
import semmle.python.Concepts
import semmle.python.ApiGraphs
import DataFlow::PathGraph

class SubprocessCalls extends DataFlow::CallNode {
  SubprocessCalls() {
    getTarget().hasQualifiedName("subprocess", ["Popen", "run", "call", "check_output"]) and
    this = API::moduleImport("subprocess").getACall()
  }
}

class CommandSource extends DataFlow::Node {
  CommandSource() {
    exists(SubprocessCalls call |
      call.getArg(0) = this and
      not this instanceof ConstantString and
      not exists(ArrayExpr array | array = this)
    )
  }
}

class ShellExecution extends DataFlow::Node {
  ShellExecution() {
    exists(SubprocessCalls call |
      call.getArg(0) = this and
      (
        this instanceof StringLiteral and this.getText().matches("%(sh|bash|ksh|csh|tcsh|zsh)%") or
        exists(call.getArg(1) | this.toString() = "-c")
      )
    )
  }
}

class ShlexSanitizer extends DataFlow::Node {
  ShlexSanitizer() {
    exists(CallNode call |
      call.getTarget().hasQualifiedName("shlex", "escape") and
      call.getResult() = this
    )
  }
}

module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof CommandSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof ShellExecution }
  predicate isSanitizer(DataFlow::Node sanitizer) { sanitizer instanceof ShlexSanitizer }
  predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(ParameterNode param | pred.asExpr() = param.getAnArgument() and succ = param)
  }
}

module DangerousSubprocess = TaintPathAnalysis::Make<TaintConfig>;

from DangerousSubprocess::PathNode source, DangerousSubprocess::PathNode sink
where DangerousSubprocess::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Detected subprocess function without a static string. If this data can " +
  "be controlled by a malicious actor, it may be an instance of command injection. " +
  "Audit the use of this call to ensure it is not controllable by an external resource. " +
  "You may consider using 'shlex.escape()'."