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
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.CommandInjection

class RequestParamSources extends DataFlow::Node {
  RequestParamSources() {
    exists(Parameter p |
      this.asParameter() = p and
      not p.getType().toString().matches("^\\b(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)\\b") and
      p.getAnAnnotation().toString().matches("(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)")
    )
  }
}

class StringConcatSources extends DataFlow::Node {
  StringConcatSources() {
    exists(DataFlow::Node source, RequestParamSources requestSource |
      (exists(AddOperation add |
        (add.getLeftOperand() = this and add.getRightOperand() = source) or
        (add.getLeftOperand() = source and add.getRightOperand() = this)
      ) or
      exists(Method m |
        (m.getName() = "format" and m.getDeclaringType().hasQualifiedName("java.lang", "String") and
          m.getACall().getAnArgument() = this) or
        (m.getName() = "join" and m.getDeclaringType().hasQualifiedName("java.lang", "String") and
          m.getACall().getAnArgument() = this) or
        ((m.getName() = "concat" and m.getDeclaringType().hasQualifiedName("java.lang", "String")) and
          (m.getACall().getQualifier() = this or m.getACall().getAnArgument() = this))
      ) or
      exists(Assignment a |
        (a.getDest() = this and a.getSource() = source) or
        (a.getDest() = source and a.getSource() = this)
      )) and
      DataFlow::localFlow(DataFlow::parameterNode(requestSource), DataFlow::exprNode(source))
    )
  }
}

class CommandSinks extends DataFlow::Node {
  CommandSinks() {
    exists(Method m |
      this.asExpr() = m.getACall().getAnArgument() and
      (
        (m.getName() = "exec" and m.getDeclaringType().hasQualifiedName("java.lang", "Runtime")) or
        (m.getName() = "command" and m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder")) or
        (m.getName() = "load" and m.getDeclaringType().hasQualifiedName("java.lang", "Runtime")) or
        (m.getName() = "loadLibrary" and m.getDeclaringType().hasQualifiedName("java.lang", "Runtime")) or
        (m.getName() = "add" and m.getDeclaringType().hasQualifiedName("java.util", "List")) or
        (m.getName() = "addAll" and m.getDeclaringType().hasQualifiedName("java.util", "List")) or
        (m.getName() = "start" and m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder"))
      )
    )
  }
}

class CommandValidationSanitizer extends DataFlow::Node {
  CommandValidationSanitizer() {
    exists(Method m |
      this.asExpr() = m.getACall() and
      m.getName() = "validateCommand" and
      m.getDeclaringType().getName() = "CommandValidationUtils"
    )
  }
}

class TaintedCommandFlowConfiguration extends TaintTracking::Configuration {
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
    exists(Method m |
      m.getName() = "append" and
      m.getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      pred.asExpr() = m.getACall().getAnArgument() and
      succ.asExpr() = m.getACall().getQualifier()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedCommandFlowConfiguration config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected user input entering a method which executes a system command. This could result in command injection."