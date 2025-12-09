/**
 * @name Dangerous Subprocess Use
 * @description Detected subprocess function without a static string. If this data can be controlled 
 *              by a malicious actor, it may be an instance of command injection.
 * @kind problem
 * @problem.severity error
 * @id python/dangerous-subprocess-use-audit
 * @tags security
 *       external/cwe/cwe-078
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import python
import DataFlow::PathGraph

predicate isSubprocessCall(DataFlow::CallNode call) {
  exists(string funcName |
    call.getTarget().getName() = funcName and
    regexMatches(".*", funcName) and
    call.getTarget().getLocation().getFile().getRelativePath().regexMatches(".*subprocess.*")
  )
}

predicate isDangerousShell(DataFlow::ValueNode arg) {
  exists(string shellPattern |
    arg.getStringValue() = shellPattern and
    shellPattern.regexMatches("^(sh|bash|ksh|csh|tcsh|zsh|python)")
  )
}

class SubprocessSource extends DataFlow::Node {
  SubprocessSource() {
    exists(DataFlow::CallNode call |
      isSubprocessCall(call) and
      this.asExpr() = call
    )
  }
}

class CommandSink extends DataFlow::Node {
  CommandSink() {
    exists(DataFlow::CallNode call, DataFlow::ValueNode arg |
      isSubprocessCall(call) and
      call.getArgument(0) = arg and
      isDangerousShell(arg) and
      this.asExpr() = arg
    )
  }
}

predicate isSanitized(DataFlow::Node node) {
  exists(DataFlow::CallNode call |
    isSubprocessCall(call) and
    call.getArgument(0).getStringValue() = "..." and
    node.asExpr() = call.getArgument(0)
  )
}

query predicate commandInjection(DataFlow::PathNode source, DataFlow::PathNode sink) {
  exists(SubprocessSource src, CommandSink snk |
    source.getNode() = src and
    sink.getNode() = snk and
    DataFlow::flowPath(src, snk)
  )
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  commandInjection(source, sink) and
  not isSanitized(source.getNode()) and
  not isSanitized(sink.getNode())
select sink.getNode(), 
"Dangerous subprocess call found. If this data is user-controlled, it could lead to command injection. " +
"Consider using shlex.escape() to sanitize inputs.", 
source.getNode(), "User input flows to command execution here"