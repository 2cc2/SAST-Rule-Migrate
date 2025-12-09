/**
 * @name Unverified SSL context in Paramiko exec_command
 * @description Detects unverified SSL context in Paramiko exec_command calls
 * @kind path-problem
 * @id python/paramiko-exec-command
 * @problem.severity error
 * @tags security
 *       injection
 *       paramiko
 *       owasp-a01
 *       owasp-a03
 *       cwe-78
 */

import python
import DataFlow::PathGraph
import semmle.python.dataflow.new.TaintTracking

class ParamikoSSHClientSource extends DataFlow::Node {
  ParamikoSSHClientSource() {
    exists(CallNode call |
      call.getTarget().hasQualifiedName("paramiko.client", "SSHClient", "exec_command") and
      not call.getArg(0).toString().regexpMatch("^\".*\"$") and
      this.asExpr() = call
    )
  }
}

class ParamikoExecCommandSink extends DataFlow::Node {
  ParamikoExecCommandSink() {
    exists(CallNode call |
      call.getTarget().hasQualifiedName("paramiko.client", "SSHClient", "exec_command") and
      not call.getArg(0).toString().regexpMatch("^\".*\"$") and
      this.asExpr() = call
    )
  }
}

class SafeExecCommandSanitizer extends DataFlow::BarrierGuard {
  SafeExecCommandSanitizer() {
    exists(CallNode call |
      call.getTarget().hasQualifiedName("paramiko.client", "SSHClient", "exec_command") and
      call.getArg(0).toString().regexpMatch("^\".*\"$") and
      this.asExpr() = call
    )
  }
}

class ParamikoExecCommandConfig extends TaintTracking::Configuration {
  ParamikoExecCommandConfig() { this = "ParamikoExecCommandConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ParamikoSSHClientSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ParamikoExecCommandSink
  }

  override predicate isSanitizer(DataFlow::BarrierGuard sanitizer) {
    sanitizer instanceof SafeExecCommandSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(CallNode call |
      call.getTarget().hasQualifiedName("paramiko.client", "SSHClient", "exec_command") and
      pred.asExpr() = call.getReceiver() and
      succ.asExpr() = call
    )
  }
}

from ParamikoExecCommandConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Unverified SSL context detected. This will permit insecure connections " +
  "without verifying SSL certificates. Use 'ssl.create_default_context()' instead.",
  source, sink