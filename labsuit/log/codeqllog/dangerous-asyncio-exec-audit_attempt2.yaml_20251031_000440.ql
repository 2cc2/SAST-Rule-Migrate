/**
 * @name Dangerous asyncio subprocess_exec without static string
 * @description Detected subprocess function 'LOOP.subprocess_exec' without a static string. 
 *              If this data can be controlled by a malicious actor, it may be an instance of 
 *              command injection. Audit the use of this call to ensure it is not controllable 
 *              by an external resource. You may consider using 'shlex.escape()'.
 * @kind path-problem
 * @problem.severity error
 * @id python/dangerous-asyncio-exec-audit
 * @tags security
 *       python
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 *       external/owasp/a01
 *       external/owasp/a03
 */

import python
import semmle.python.dataflow.DataFlow
import semmle.python.dataflow.TaintTracking

class DangerousSubprocessExecConfiguration extends TaintTracking::Configuration {
  DangerousSubprocessExecConfiguration() { this = "DangerousSubprocessExecConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "subprocess_exec" and
      ma.getMethod().getDeclaringType().getName() = "loop" and
      ma.getMethod().getDeclaringType().getAPackage().getName() = "asyncio" and
      not ma.getArgument(1).getStringValue().matches("^.+$") and
      not ma.getArgument(1).getElements()[0].getStringValue().matches("^(sh|bash|ksh|csh|tcsh|zsh)$") and
      source.asExpr() = ma.getArgument(1)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "subprocess_exec" and
      ma.getMethod().getDeclaringType().getName() = "loop" and
      ma.getMethod().getDeclaringType().getAPackage().getName() = "asyncio" and
      ma.getArgument(1).getStringValue().matches("^(sh|bash|ksh|csh|tcsh|zsh)$") and
      ma.getArgument(2).getStringValue() = "-c" and
      sink.asExpr() = ma.getArgument(1)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "escape" and
      ma.getMethod().getDeclaringType().getName() = "shlex" and
      sanitizer.asExpr() = ma
    )
  }
}

from DangerousSubprocessExecConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source.getNode(), 
  "Detected subprocess function '$LOOP.subprocess_exec' without a static string. " +
  "If this data can be controlled by a malicious actor, it may be an instance of " +
  "command injection. Audit the use of this call to ensure it is not controllable " +
  "by an external resource. You may consider using 'shlex.escape()'."