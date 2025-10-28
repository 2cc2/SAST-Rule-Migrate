/**
 * @name Paramiko exec_command unverified command execution
 * @description Detects unverified command execution through Paramiko's SSHClient.exec_command without proper input sanitization
 * @kind path-problem
 * @problem.severity error
 * @id python/paramiko-exec-command
 */

import python
import semmle.python.security.strings.Untrusted
import semmle.python.security.injection.RemoteCommandInjection
import DataFlow::PathGraph

class SSHClientCreation extends DataFlow::Node {
  SSHClientCreation() {
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("paramiko.client", "SSHClient") and
      mc.getMethod().getName() = "SSHClient" and
      this.asExpr() = mc
    )
  }
}

class ExecCommandCall extends DataFlow::Node {
  ExecCommandCall() {
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("paramiko.client", "SSHClient") and
      mc.getMethod().getName() = "exec_command" and
      this.asExpr() = mc.getArgument(0) and
      not mc.getArgument(0).getStringValue().regexpMatch("\\.\\.\\.")
    )
  }
}

class ParamikoCommandInjectionConfig extends TaintTracking::Configuration {
  ParamikoCommandInjectionConfig() { this = "ParamikoCommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SSHClientCreation
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ExecCommandCall
  }
}

from ParamikoCommandInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Unverified command execution detected. " +
  "This will permit execution of potentially malicious commands. " +
  "Always validate and sanitize command inputs."