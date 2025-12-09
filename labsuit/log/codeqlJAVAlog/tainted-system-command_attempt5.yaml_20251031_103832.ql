/**
 * @id tainted-system-command
 * @severity ERROR
 * @name OS Command Injection
 * @description Detected user input entering a method which executes a system command. This could result in a command injection vulnerability, which allows an attacker to inject an arbitrary system command onto the server.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 *       owasp-a1
 *       owasp-a03
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class RequestSource extends DataFlow::Node {
  RequestSource() {
    this instanceof Parameter and
    not this.getType().toString().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)$") and
    exists(string anno | this.getAnAnnotation().getType().toString().matches("(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)") |
      anno = this.getAnAnnotation().getType().toString()
    )
  }
}

class StringConcatSource extends DataFlow::Node {
  StringConcatSource() {
    exists(BinaryExpr bin |
      bin.getOp() = ADD and
      (bin.getLeftOperand() = this or bin.getRightOperand() = this) and
      bin.getLeftOperand().getType() instanceof TypeString and
      bin.getRightOperand().getType() instanceof TypeString
    ) or
    exists(MethodAccess call |
      call.getMethod().getName().matches("format|join|concat") and
      this = call.getAnArgument()
    ) or
    exists(Assignment assign |
      (assign.getDest() instanceof LocalVariableExpr or
       assign.getDest() instanceof FieldAccess) and
      assign.getSource() = this
    )
  }
}

class CommandSink extends DataFlow::Node {
  CommandSink() {
    exists(MethodAccess exec |
      (exec.getMethod().getName() = "exec" and
       exec.getReceiverType().toString() = "Runtime") or
      (exec.getMethod().getName() = "command" and
       exec.getReceiverType().toString() = "ProcessBuilder") or
      (exec.getMethod().getName() = "load" and
       exec.getReceiverType().toString() = "Runtime") or
      (exec.getMethod().getName() = "loadLibrary" and
       exec.getReceiverType().toString() = "Runtime") or
      (exec.getMethod().getName() = "start" and
       exec.getReceiverType().toString() = "ProcessBuilder")
    ) and
    this = exec.getAnArgument()
  }
}

class CommandSanitizer extends DataFlow::Node {
  CommandSanitizer() {
    exists(MethodAccess validate |
      validate.getMethod().getName() = "validateCommand" and
      validate.getReceiverType().toString().matches("CommandValidationUtils")
    )
  }
}

class TaintedCommandConfig extends TaintTracking::Configuration {
  TaintedCommandConfig() { this = "TaintedCommandConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RequestSource or
    source instanceof StringConcatSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof CommandSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess appendCall |
      appendCall.getMethod().getName() = "append" and
      appendCall.getReceiverType().toString() = "StringBuilder" and
      pred = appendCall.getAnArgument() and
      succ = appendCall
    )
  }
}

from TaintedCommandConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Detected user input entering a method which executes a system command. This could result in a command injection vulnerability."