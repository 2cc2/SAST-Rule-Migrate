/**
 * @name Dangerous asyncio.exec without static string
 * @description Detected subprocess function '$LOOP.subprocess_exec' without a static string.
 *              If this data can be controlled by a malicious actor, it may be an instance
 *              of command injection. Audit the use of this call to ensure it is not controllable
 *              by an external resource. You may consider using 'shlex.escape()'.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id python/dangerous-asyncio-exec-audit
 * @tags security
 *       external/cwe/cwe-078
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import DataFlow::PathGraph

predicate isSubprocessExec(Node node) {
  exists(MethodAccess ma | 
    ma.getMethod().getName() = "subprocess_exec" and
    ma.getReceiver().getType().getName() = "loop" and
    ma.getReceiver().getType().getASourceFile().getRelativePath().matches("asyncio.*"))

predicate isDynamicArgument(DataFlow::Node arg) {
  not arg.asExpr().toString() matches(/^.+$/) or
  not arg.asExpr().getFirstExpr().toString() matches(/^(sh|bash|ksh|csh|tcsh|zsh)$/)
}

predicate isShellArgument(DataFlow::Node arg) {
  arg.asExpr().toString() matches(/^(sh|bash|ksh|csh|tcsh|zsh)$/) and
  arg.asDistance(1).asExpr().toString() = "-c"
}

predicate isProtectedByShlex(DataFlow::Node arg) {
  exists(MethodAccess ma |
    ma.getMethod().getName() = "escape" and
    ma.getReceiver().getType().getName() = "shlex" and
    DataFlow::localFlow(ma.getResult(), arg))
}

class DangerousSubprocessExecConfig extends TaintTracking::Configuration {
  DangerousSubprocessExecConfig() { this = "DangerousSubprocessExecConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      isSubprocessExec(ma) and
      source.asParameter() = ma.getArgument(1) and
      isDynamicArgument(source))
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      isSubprocessExec(ma) and
      sink.asParameter() = ma.getArgument(1) and
      isShellArgument(sink))
  }

  override predicate isSanitizer(DataFlow::Node node) {
    isProtectedByShlex(node)
  }
}

from DangerousSubprocessExecConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), "Detected subprocess function '$LOOP.subprocess_exec' without a static string. " +
  "If this data can be controlled by a malicious actor, it may be an instance of command injection. " +
  "Audit the use of this call to ensure it is not controllable by an external resource. " +
  "You may consider using 'shlex.escape()'.", source.getNode(), "Potentially unsafe command source"