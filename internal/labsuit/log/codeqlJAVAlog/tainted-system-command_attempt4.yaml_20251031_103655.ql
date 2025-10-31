/**
 * @name Tainted system command
 * @description Detected user input entering a method which executes a system command. This could result in a command injection vulnerability.
 * @kind path-problem
 * @problem.severity error
 * @id java/tainted-system-command
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 *       owasp-a1
 *       owasp-a3
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class RequestSource extends DataFlow::Node {
  RequestSource() {
    exists(Method m, Parameter p |
      m.getAnAnnotation().toString().matches("%(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)%") and
      p = m.getAParameter() and
      this.asParameter() = p and
      not p.getType().getName().matches("%(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)%")
    )
  }
}

class StringConcat extends DataFlow::Node {
  StringConcat() {
    exists(BinaryOperation b |
      b.getOperator().toString() = "+" and
      (this = b.getLeftOperand() or this = b.getRightOperand())
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("concat") and
      this = ma.getQualifier()
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      this = ma.getAnArgument()
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("join") and
      this = ma.getAnArgument()
    )
    or
    exists(AssignmentExpr ae |
      ae.getOperator().toString() = "+=" and
      this = ae.getTarget()
    )
  }
}

class CommandExecutionSink extends DataFlow::Node {
  CommandExecutionSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().hasName("exec") and
        ma.getQualifier().getType().hasName("Runtime")
      )
      or
      (
        ma.getMethod().hasName("command") and
        ma.getQualifier().getType().hasName("ProcessBuilder")
      )
      or
      (
        ma.getMethod().hasName("start") and
        ma.getQualifier().getType().hasName("ProcessBuilder")
      )
      or
      (
        ma.getMethod().hasName("load") and
        ma.getQualifier().getType().hasName("Runtime")
      )
      or
      (
        ma.getMethod().hasName("loadLibrary") and
        ma.getQualifier().getType().hasName("Runtime")
      )
    )
  }
}

class CommandValidationSanitizer extends DataFlow::Node {
  CommandValidationSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "validateCommand" and
      ma.getQualifier().getType().hasName("CommandValidationUtils")
    )
  }
}

class TaintedCommandConfig extends TaintTracking::Configuration {
  TaintedCommandConfig() { this = "TaintedCommandConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RequestSource
    or
    source instanceof StringConcat
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandExecutionSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof CommandValidationSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "append" and
      ma.getQualifier().getType().hasName("StringBuilder") and
      pred.asExpr() = ma.getAnArgument() and
      succ.asExpr() = ma
    )
  }
}

from TaintedCommandConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potentially tainted data reaches command execution ($@)", sink,
  "User input reaches command execution"