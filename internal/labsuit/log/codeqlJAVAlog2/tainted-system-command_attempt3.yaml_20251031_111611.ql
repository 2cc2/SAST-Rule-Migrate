/**
 * @name Tainted System Command
 * @description Detected user input entering a method which executes a system command.
 * @id tainted-system-command
 * @kind path-problem
 * @security-severity 8.8
 * @problem.severity error
 */
import java
import DataFlow
import TaintTracking
import semmle.code.java.frameworks.spring.SpringController

class RequestParamSources extends DataFlow::Node {
  RequestParamSources() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet", "ServletRequest") or
      exists(Annotation a |
        a.getType().getASupertype*().hasQualifiedName(["org.springframework.web.bind.annotation"],
          ["RequestBody", "PathVariable", "RequestParam", "RequestHeader", "CookieValue", "ModelAttribute"]) and
        this.asExpr() = ma.getAnArgument()
      )
    ) and
    not this.getType().hasName(["Integer", "Long", "Float", "Double", "Char", "Boolean", "int", "long", "float", "double", "char", "boolean"])
  }
}

class StringConcatenation extends DataFlow::Node {
  StringConcatenation() {
    exists(BinaryExpr be |
      be.getOperator() = "+" and
      (this.asExpr() = be.getLeftOperand() or this.asExpr() = be.getRightOperand()) and
      exists(DataFlow::Node source | source instanceof RequestParamSources | 
        DataFlow::localFlow(DataFlow::exprNode(source.asExpr()), DataFlow::exprNode(this.asExpr()))
      )
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("format|join|concat") and
      this.asExpr() = ma and
      exists(DataFlow::Node source | source instanceof RequestParamSources |
        DataFlow::localFlow(DataFlow::exprNode(source.asExpr()), DataFlow::exprNode(this.asExpr()))
      )
    )
  }
}

class CommandSinks extends DataFlow::Node {
  CommandSinks() {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
       ma.getMethod().getName().matches("exec|load|loadLibrary"))
      or
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
       ma.getMethod().getName().matches("command|start|add|addAll"))
    )
  }
}

class CommandValidationSanitizer extends DataFlow::BarrierGuard {
  CommandValidationSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("validateCommand") and
      ma.getMethod().getDeclaringType().hasName("CommandValidationUtils") and
      this.asExpr() = ma
    )
  }
}

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RequestParamSources or source instanceof StringConcatenation
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
      DataFlow::localFlow(DataFlow::exprNode(pred.asExpr()), DataFlow::exprNode(ma.getAnArgument())) and
      DataFlow::localFlow(DataFlow::exprNode(ma), DataFlow::exprNode(succ.asExpr()))
    )
  }
}

from CommandInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, "Detected user input entering a method which executes a system command. This could result in a command injection vulnerability."