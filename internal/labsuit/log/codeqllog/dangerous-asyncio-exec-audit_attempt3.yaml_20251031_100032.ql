/**
 * @name Dangerous asyncio.subprocess_exec usage
 * @description Detected subprocess function '$LOOP.subprocess_exec' without a static string.
 * @id dangerous-asyncio-exec-audit
 * @kind path-problem
 * @problem.severity error
 * @tags security
 *       python
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */
import python
import semmle.python.ApiGraphs
import DataFlow::PathGraph

class AsyncioSubprocessExecConfig extends DataFlow::Configuration {
  AsyncioSubprocessExecConfig() { this = "AsyncioSubprocessExecConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Call call |
      call.getCallee().(QualifiedName).matches("asyncio.loop.subprocess_exec") and
      (
        not exists(call.getArgumentAt(1).getStringValue().regexpMatch(".+")) or
        not exists(call.getArgumentAt(1).getStringValue().regexpMatch("^(sh|bash|ksh|csh|tcsh|zsh)$"))
      ) and
      source.asExpr() = call.getArgumentAt(1)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getCallee().(QualifiedName).matches("asyncio.loop.subprocess_exec") and
      call.getArgumentAt(1).getStringValue().regexpMatch("^(sh|bash|ksh|csh|tcsh|zsh)$") and
      call.getArgumentAt(2).getStringValue() = "-c" and
      sink.asExpr() = call.getArgumentAt(1)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Call call |
      call.getCallee().(QualifiedName).matches("shlex.escape") and
      sanitizer.asExpr() = call
    )
  }
}

from AsyncioSubprocessExecConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink,
  "Detected subprocess function 'subprocess_exec' without a static string. If this data can be controlled by a malicious actor, it may be an instance of command injection. Consider using 'shlex.escape()'."