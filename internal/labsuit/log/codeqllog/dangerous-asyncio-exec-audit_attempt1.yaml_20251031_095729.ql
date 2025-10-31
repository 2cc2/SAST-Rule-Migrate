/**
 * @name Dangerous asyncio.exec audit
 * @description Detected subprocess function '$LOOP.subprocess_exec' without a static string. 
 *              If this data can be controlled by a malicious actor, it may be an instance 
 *              of command injection. Audit the use of this call to ensure it is not 
 *              controllable by an external resource. You may consider using 'shlex.escape()'.
 * @kind taint
 * @problem.severity error
 * @id python/dangerous-asyncio-exec-audit
 * @tags security
 *       python
 *       asyncio
 *       owasp-a01
 *       owasp-a03
 *       cwe-78
 */

import python
import semmle.python.security.TaintTracking
import semmle.python.Concepts

class DangerousSubprocessExecConfig extends TaintTracking::Configuration {
  DangerousSubprocessExecConfig() { this = "Dangerous asyncio.exec audit" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodCall call |
      call.getMethod().getName() = "subprocess_exec" and
      call.getReceiver().getType().getName() = "loop" and
      call.getReceiver().getType().getModule().getName() = "asyncio" and
      not call.getArgument(1).getValue().matches(".+") and
      not call.getArgument(1).getElements()[0].getValue().matches("^(sh|bash|ksh|csh|tcsh|zsh)$") and
      source.asExpr() = call.getArgument(1)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethod().getName() = "subprocess_exec" and
      call.getReceiver().getType().getName() = "loop" and
      call.getReceiver().getType().getModule().getName() = "asyncio" and
      call.getArgument(1).getValue().matches("^(sh|bash|ksh|csh|tcsh|zsh)$") and
      call.getArgument(2).getValue() = "-c" and
      sink.asExpr() = call.getArgument(2)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodCall call |
      call.getMethod().getName() = "escape" and
      call.getReceiver().getType().getName() = "shlex" and
      sanitizer.asExpr() = call
    )
  }
}