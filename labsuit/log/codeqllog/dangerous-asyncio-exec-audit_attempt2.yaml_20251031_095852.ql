/**
 * @name Dangerous asyncio subprocess_exec call
 * @description Detected subprocess function '$LOOP.subprocess_exec' without a static string. If this data can be controlled by a malicious actor, it may be an instance of command injection.
 * @id python/dangerous-asyncio-exec-audit
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @tags security
 *       python
 *       injection
 *       external/cwe/cwe-078
 */

import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts

class DangerousSubprocessExecConfig extends TaintTracking::Configuration {
  DangerousSubprocessExecConfig() { this = "DangerousSubprocessExecConfig" }

  override predicate isSource(TaintTracking::TaintSource source) {
    exists(Call call |
      call.getTarget().hasQualifiedName("asyncio.loop", "subprocess_exec") and
      not call.getArgument(1).getValue().regexpMatch("^.+$") and
      not call.getArgument(1).getElements().get(0).getValue().regexpMatch("^(sh|bash|ksh|csh|tcsh|zsh)$")
    )
  }

  override predicate isSink(TaintTracking::TaintSink sink) {
    exists(Call call |
      call.getTarget().hasQualifiedName("asyncio.loop", "subprocess_exec") and
      call.getArgument(1).getValue().regexpMatch("^(sh|bash|ksh|csh|tcsh|zsh)$") and
      call.getArgument(2).getValue() = "-c"
    )
  }

  override predicate isSanitizer(TaintTracking::Sanitizer sanitizer) {
    exists(Call call |
      call.getTarget().hasQualifiedName("shlex", "escape") and
      sink.asExpr() = call.getArgument(0).asExpr()
    )
  }
}

from DangerousSubprocessExecConfig cfg
select cfg