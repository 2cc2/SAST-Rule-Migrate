/**
 * @name Tainted System Command
 * @description Detected user input entering a method which executes a system command.
 * @id tainted-system-command
 * @kind path-problem
 * @security-severity 8.8
 * @problem.severity error
 */
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class RequestParamSources extends DataFlow::Node {
  RequestParamSources() {
    exists(Method m |
      m.getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet", "ServletRequest") or
      exists(Annotation ann |
        ann.getType().getASupertype*().hasQualifiedName(
          "org.springframework.web.bind.annotation",
          ["RequestBody", "PathVariable", "RequestParam", "RequestHeader", "CookieValue", "ModelAttribute"]
        ) and
        ann.getAnnotatedElement() = this.asParameter()
      )
    ) and
    not this.getUnderlyingType().hasName(["Integer", "Long", "Float", "Double", "Char", "Boolean", 
                                        "int", "long", "float", "double", "char", "boolean"])
  }
}

class StringConcatenation extends DataFlow::Node {
  StringConcatenation() {
    exists(BinaryExpr be |
      be.getOperator() = "+" and
      (this.asExpr() = be.getLeftOperand() or this.asExpr() = be.getRightOperand()) and
      exists(RequestParamSources source | 
        DataFlow::localExprFlow(source.asExpr(), this.asExpr())
      )
    )
    or
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "format" or 
       ma.getMethod().getName() = "join" or 
       ma.getMethod().getName() = "concat") and
      this.asExpr() = ma and
      exists(RequestParamSources source | 
        DataFlow::localExprFlow(source.asExpr(), this.asExpr())
      )
    )
  }
}

class CommandSinks extends DataFlow::Node {
  CommandSinks() {
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
       regexpMatch(ma.getMethod().getName(), "exec|load|loadLibrary"))
      or
      (ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
       regexpMatch(ma.getMethod().getName(), "command|start|add|addAll"))
    )
  }
}

class CommandValidationSanitizer extends TaintTracking::BarrierGuard {
  CommandValidationSanitizer() {
    exists(MethodAccess ma |
      regexpMatch(ma.getMethod().getName(), "validateCommand") and
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
      DataFlow::localExprFlow(DataFlow::exprNode(pred.asExpr()), DataFlow::exprNode(ma.getAnArgument())) and
      DataFlow::localExprFlow(DataFlow::exprNode(ma), DataFlow::exprNode(succ.asExpr()))
    )
  }
}

from CommandInjectionConfig config, TaintTracking::PathNode source, TaintTracking::PathNode sink
where config.hasFlowPath(source, sink)
select sink, "Detected user input entering a method which executes a system command. This could result in a command injection vulnerability."