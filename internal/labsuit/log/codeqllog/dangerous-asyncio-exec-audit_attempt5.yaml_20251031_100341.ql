/**
 * @name Dangerous asyncio subprocess execution
 * @description Detected subprocess function call without a static string verification.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id python/dangerous-asyncio-exec-audit
 * @tags security
 *       python
 *       asyncio
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import semmle.python.ApiGraphs
import DataFlow::PathGraph
import TaintTracking::Configuration

class AsyncioLoopConfig extends TaintTracking::Configuration {
  AsyncioLoopConfig() { this = "AsyncioLoopConfig" }

  override predicate isSource(TaintTracking::TaintSource source) {
    exists(CallNode call |
      call.getMethod() instanceof AsyncioSubprocessExecMethod and
      not call.getArg(1).getStringValue().matches("^.+$") and
      not call.getArg(1).getChild(0).getStringValue().matches("^(sh|bash|ksh|csh|tcsh|zsh)$") and
      source.asRegisterSource().controls(call, _)
    )
  }

  override predicate isSink(TaintTracking::TaintSink sink) {
    exists(CallNode call |
      call.getMethod() instanceof AsyncioSubprocessExecMethod and
      call.getArg(1).getStringValue().matches("^(sh|bash|ksh|csh|tcsh|zsh)$") and
      call.getArg(2).getStringValue() = "-c" and
      sink.asRegisterSink().controls(call, _)
    )
  }

  override predicate isSanitizer(TaintTracking::Sanitizer sanitizer) {
    exists(CallNode call |
      call.getMethod() instanceof ShlexEscapeMethod and
      sanitizer.asRegisterSanitizer().controls(call, _)
    )
  }
}

class AsyncioSubprocessExecMethod extends Method {
  AsyncioSubprocessExecMethod() {
    this.getDeclaringType().getQualifiedName() = "asyncio.loop" and
    this.getName() = "subprocess_exec"
  }
}

class ShlexEscapeMethod extends Method {
  ShlexEscapeMethod() {
    this.getDeclaringType().getQualifiedName() = "shlex" and
    this.getName() = "escape"
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  any(AsyncioLoopConfig cfg).hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Detected subprocess function call without a static string. Audit the use of this call to ensure it is not controllable by an external resource. Consider using 'shlex.escape()'."