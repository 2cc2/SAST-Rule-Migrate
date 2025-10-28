/**
 * @name Dangerous asyncio.exec audit
 * @description Detected subprocess function '$LOOP.subprocess_exec' without a static string. If this data can be controlled
 *              by a malicious actor, it may be an instance of command injection. Audit the use of this call to ensure it is
 *              not controllable by an external resource. You may consider using 'shlex.escape()'.
 * @kind path-problem
 * @problem.severity error
 * @id py/dangerous-asyncio-exec-audit
 */

import python
import semmle.python.security.Paths
import semmle.python.Concepts
import semmle.python.ApiGraphs

class DangerousSubprocessExec extends MethodCall {
  DangerousSubprocessExec() {
    this.getMethod().hasName(["subprocess_exec"]) and
    exists(MethodAccess ma |
      ma.getMethod().hasName(["subprocess_exec"]) and
      this = ma
    )
  }
  
  predicate isStaticString(Expr arg) {
    exists(StringLiteral sl | arg = sl)
  }
  
  predicate isShellCommand(Expr arg) {
    exists(DataFlow::StringConstExpr sce |
      arg = sce.getExpr() and
      regexpMatch(".*(sh|bash|ksh|csh|tcsh|zsh).*", sce.getValue())
    )
  }
  
  predicate hasShellOption(Expr arg) {
    exists(StringLiteral sl |
      arg = sl and
      sl.getStringValue() = "-c"
    )
  }
}

class DangerousSubprocessExecConfiguration extends TaintTracking::Configuration {
  DangerousSubprocessExecConfiguration() { this = "DangerousSubprocessExecConfiguration" }
  
  override predicate isSource(DataFlow::Node source) {
    exists(DangerousSubprocessExec dse |
      source.asExpr() = dse.getAnArgument() and
      not dse.isStaticString(dse.getAnArgument())
    )
  }
  
  override predicate isSink(DataFlow::Node sink) {
    exists(DangerousSubprocessExec dse |
      sink.asExpr() = dse.getAnArgument(0) and
      dse.isShellCommand(dse.getAnArgument(0)) and
      dse.hasShellOption(dse.getAnArgument(1))
    )
  }
  
  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(DangerousSubprocessExec dse |
      sanitizer.asExpr() = dse.getAnArgument() and
      dse.isStaticString(dse.getAnArgument())
    )
  }
}

from DangerousSubprocessExecConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Detected subprocess_exec call with potential command injection vulnerability."