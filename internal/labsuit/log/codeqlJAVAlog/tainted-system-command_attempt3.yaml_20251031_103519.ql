/**
 * @name Tainted system command
 * @description Detected user input entering a method which executes a system command.
 * @kind problem
 * @severity error
 * @id java/tainted-system-command
 * @tags security
 *       external/cwe/cwe-078
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class RequestSource extends DataFlow::Node {
  RequestSource() {
    exists(Parameter p |
      p = this.asParameter() and
      not p.getType().hasName(["Integer", "Long", "Float", "Double", "Char", "Boolean",
                              "int", "long", "float", "double", "char", "boolean"]) and
      p.getAnAnnotation().getType().hasName([
        "RequestBody", "PathVariable", "RequestParam", 
        "RequestHeader", "CookieValue", "ModelAttribute"
      ])
    )
  }
}

class StringConcat extends DataFlow::Node {
  StringConcat() {
    exists(BinaryExpr b | b = this.asExpr() | b.getOp() instanceof Add and b.getType() instanceof TypeString) or
    exists(MethodAccess m | m = this.asExpr() | 
      m.getMethod().getName().matches("format|join|concat") and
      m.getMethod().getDeclaringType() instanceof TypeString
    ) or
    exists(AssignExpr a | a = this.asExpr() | 
      a.getOp() instanceof AssignAdd and a.getType() instanceof TypeString
    )
  }
}

class CommandExecutionSink extends DataFlow::Node {
  CommandExecutionSink() {
    exists(MethodAccess m | m = this.asExpr() |
      m.getMethod().getName() = "exec" or
      m.getMethod().getName() = "command" or
      m.getMethod().getName() = "load" or
      m.getMethod().getName() = "loadLibrary" or
      m.getMethod().getName() = "add" or
      m.getMethod().getName() = "addAll" or
      m.getMethod().getName() = "start"
    )
  }
}

class CommandValidationSanitizer extends DataFlow::Node {
  CommandValidationSanitizer() {
    exists(MethodAccess m | m = this.asExpr() | 
      m.getMethod().getName() = "validateCommand" and
      m.getMethod().getDeclaringType().getName() = "CommandValidationUtils"
    )
  }
}

class StringBuilderConcat extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess m | 
      m.getMethod().getName() = "append" and
      m.getMethod().getDeclaringType() instanceof StringBuilderType and
      pred.asExpr() = m.getAnArgument() and
      succ.asExpr() = m
    )
  }
}

class TaintedCommandConfig extends TaintTracking::Configuration {
  TaintedCommandConfig() { this = "TaintedCommandConfig" }

  override predicate isSource(DataFlow::Node source) { 
    source instanceof RequestSource 
  }

  override predicate isSink(DataFlow::Node sink) { 
    sink instanceof CommandExecutionSink 
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof CommandValidationSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    StringBuilderConcat::step(pred, succ)
  }
}

from DataFlow::Node source, DataFlow::Node sink
where
  any(TaintedCommandConfig conf).hasFlow(source, sink)
select sink, "Detected user input entering a method which executes a system command."