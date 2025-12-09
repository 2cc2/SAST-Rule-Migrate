/**
 * @name Tainted system command
 * @description Detected user input entering a method which executes a system command. 
 * This could result in a command injection vulnerability, which allows an attacker 
 * to inject an arbitrary system command onto the server.
 * @kind problem
 * @precision high
 * @id java/tainted-system-command
 * @tags security
 *       cwe/cwe-78
 *       owasp/a01:2017
 *       owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.DataFlowPath
import semmle.code.java.frameworks.ProcessBuilderExec

class RequestParamSources extends DataFlow::Node {
  RequestParamSources() {
    exists(MethodParameter p |
      p = this.asParameter() and
      not p.getType().toString().matches("%^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)%$") and
      p.getAnAnnotation().toString().matches("%(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)%")
    )
  }
}

class StringConcatSources extends DataFlow::Node {
  StringConcatSources() {
    exists(DataFlow::Node source |
      exists(AddExpr add |
        (add.getLeftOperand() = this and add.getRightOperand() = source) or
        (add.getLeftOperand() = source and add.getRightOperand() = this)
      ) or
      exists(MethodAccess ma |
        (ma.getMethod().getName() = "format" and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
          ma.getAnArgument() = this) or
        (ma.getMethod().getName() = "join" and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
          ma.getAnArgument() = this) or
        ((ma.getMethod().getName() = "concat" and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")) and
          (ma.getQualifier() = this or ma.getAnArgument() = this))
      ) or
      exists(AssignExpr ae |
        (ae.getDest() = this and ae.getSource() = source) or
        (ae.getDest() = source and ae.getSource() = this)
      )
    ) and
    exists(RequestParamSources requestSource |
      DataFlow::localFlow(DataFlow::exprNode(requestSource), DataFlow::exprNode(source))
    )
  }
}

class StringBuilderConcat extends DataFlow::Node {
  StringBuilderConcat() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "append" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      ma.getAnArgument() = this
    )
  }
}

class CommandSinks extends DataFlow::Node {
  CommandSinks() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getName() = "exec" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime")
      ) or
      (
        ma.getMethod().getName() = "command" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder")
      ) or
      (
        ma.getMethod().getName() = "load" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime")
      ) or
      (
        ma.getMethod().getName() = "loadLibrary" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime")
      ) or
      (
        ma.getMethod().getName() = "add" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "List")
      ) or
      (
        ma.getMethod().getName() = "addAll" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "List")
      ) or
      (
        ma.getMethod().getName() = "start" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder")
      )
    )
  }
}

class CommandValidationSanitizer extends DataFlow::Node {
  CommandValidationSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "validateCommand" and
      ma.getMethod().getDeclaringType().getName() = "CommandValidationUtils"
    )
  }
}

class TaintedCommandFlowConfiguration extends DataFlow::Configuration {
  TaintedCommandFlowConfiguration() { this = "TaintedCommandFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RequestParamSources or
    source instanceof StringConcatSources
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandSinks
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof CommandValidationSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "append" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      pred.asExpr() = ma.getAnArgument() and
      succ.asExpr() = ma.getQualifier()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedCommandFlowConfiguration config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected user input entering a method which executes a system command. This could result in command injection."