/**
 * @name Dangerous asyncio subprocess_exec without static string
 * @description Detected subprocess function call without a static string.
 *              If this data can be controlled by a malicious actor, 
 *              it may be an instance of command injection.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id python/dangerous-asyncio-exec-audit
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 *       external/owasp/a01
 *       external/owasp/a03
 */
import python
import semmle.python.dataflow.TaintTracking
import semmle.python.Concepts

class DangerousSubprocessExecConfig extends TaintTracking::Configuration {
  DangerousSubprocessExecConfig() { this = "DangerousSubprocessExecConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Call call |
      call.getTarget().hasQualifiedName("asyncio.loop", "subprocess_exec") and
      (
        not call.getArgument(1).getStringValue().regexpMatch(".+") or
        not call.getArgument(1).getAnArgument().getStringValue().regexpMatch("^(sh|bash|ksh|csh|tcsh|zsh)$")
      ) and
      source.asExpr() = call.getArgument(1)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getTarget().hasQualifiedName("asyncio.loop", "subprocess_exec") and
      call.getArgument(1).getStringValue().regexpMatch("^(sh|bash|ksh|csh|tcsh|zsh)$") and
      call.getArgument(2).getStringValue() = "-c" and
      sink.asExpr() = call.getArgument(1)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Call call |
      call.getTarget().hasQualifiedName("shlex", "escape") and
      sanitizer.asExpr() = call
    )
  }
}

from DangerousSubprocessExecConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected subprocess function 'asyncio.loop.subprocess_exec' without a static string. $@",
  source.getNode(), "User input from here",
  sink.getNode(), "Potential command injection sink"