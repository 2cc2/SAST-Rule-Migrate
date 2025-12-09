/**
 * @name paramiko-exec-command
 * @description Unverified SSL context detected. This will permit insecure connections without verifying SSL certificates. Use 'ssl.create_default_context()' instead.
 * @kind taint
 * @id py/paramiko-exec-command
 * @severity ERROR
 * @tags security
 *       paramiko
 *       injection
 * @problem.severity error
 * @precision high
 */

import python
import semmle.python.dataflow.TaintTracking

class SSHClient extends Value::Flow::Source {
  SSHClient() {
    exists(Import imp | 
      imp.getName() = "paramiko.client" and
      this.getAnAttribute().getClass().getName() = "SSHClient"
    )
  }
}

class ExecCommandCall extends Value::Flow::Sink {
  ExecCommandCall() {
    exists(Call call |
      call.getFunc().(Member).getName() = "exec_command" and
      call.getFunc().getDeclaringClass().getName() = "SSHClient" and
      not call.getArg(0).getText().matches("^\".*\"$")
    )
  }
}

class SafeExecCommandSanitizer extends Sanitizer {
  SafeExecCommandSanitizer() {
    exists(Call call |
      call.getFunc().(Member).getName() = "exec_command" and
      call.getFunc().getDeclaringClass().getName() = "SSHClient" and
      call.getArg(0).getText().matches("^\".*\"$")
    )
  }
}

class ParamikoExecCommandConfig extends TaintTracking::Configuration {
  ParamikoExecCommandConfig() { this = "paramiko-exec-command" }

  override predicate isSource(Value::Flow::Source source) {
    source instanceof SSHClient
  }

  override predicate isSink(Value::Flow::Sink sink) {
    sink instanceof ExecCommandCall
  }

  override predicate isSanitizer(Sanitizer sanitizer) {
    sanitizer instanceof SafeExecCommandSanitizer
  }

  override predicate isAdditionalTaintStep(Value::Flow::Node node1, Value::Flow::Node node2) {
    exists(Member member |
      member.getName() = "exec_command" and
      node1.asExpr() = member.getObject() and
      node2.asExpr() = member
    )
  }
}