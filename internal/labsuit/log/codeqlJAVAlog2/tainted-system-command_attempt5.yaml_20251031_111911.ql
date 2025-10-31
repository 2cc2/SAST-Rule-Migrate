/**
 * @name Tainted System Command
 * @description Detected user input entering a method which executes a system command.
 * @id tainted-system-command
 * @kind path-problem
 * @security-severity 8.8
 * @problem.severity error
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Annotations

class RequestParamSources extends TaintTracking::AdditionalTaintStep {
  RequestParamSources() {
    exists(MethodImpl m |
      m.getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet", "ServletRequest") or
      exists(AnnotationImpl ann |
        ann.getType().getASupertype*().hasQualifiedName(
          "org.springframework.web.bind.annotation",
          ["RequestBody", "PathVariable", "RequestParam", "RequestHeader", "CookieValue", "ModelAttribute"]
        ) and
        ann.getAnnotatedElement() = this.getAParameter()
      )
    ) and
    not this.getType().hasName(["Integer", "Long", "Float", "Double", "Char", "Boolean", 
                              "int", "long", "float", "double", "char", "boolean"])
  }
}

class StringConcatenation extends TaintTracking::AdditionalTaintStep {
  StringConcatenation() {
    exists(BinaryOperation be |
      be.getOperator() = "+" and
      (this.getAChild() = be.getLeftOperand() or this.getAChild() = be.getRightOperand()) and
      exists(RequestParamSources source | 
        TaintTracking::localTaintStep(source.getAChild(), this.getAChild())
      )
    )
    or
    exists(CallExpr ma |
      (ma.getTarget().getName() = "format" or 
       ma.getTarget().getName() = "join" or 
       ma.getTarget().getName() = "concat") and
      this.getAChild() = ma and
      exists(RequestParamSources source | 
        TaintTracking::localTaintStep(source.getAChild(), this.getAChild())
      )
    )
  }
}

class CommandSinks extends TaintTracking::AdditionalTaintStep {
  CommandSinks() {
    exists(CallExpr ma |
      (ma.getTarget().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
       matches(ma.getTarget().getName(), "exec|load|loadLibrary"))
      or
      (ma.getTarget().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
       matches(ma.getTarget().getName(), "command|start|add|addAll"))
    )
  }
}

class CommandValidationSanitizer extends TaintTracking::BarrierGuard {
  CommandValidationSanitizer() {
    exists(CallExpr ma |
      matches(ma.getTarget().getName(), "validateCommand") and
      ma.getTarget().getDeclaringType().hasName("CommandValidationUtils") and
      this.getAChild() = ma
    )
  }
}

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjectionConfig" }

  override predicate isSource(TaintTracking::Source source) {
    source instanceof RequestParamSources or source instanceof StringConcatenation
  }

  override predicate isSink(TaintTracking::Sink sink) {
    sink instanceof CommandSinks
  }

  override predicate isSanitizer(TaintTracking::Sanitizer sanitizer) {
    sanitizer instanceof CommandValidationSanitizer
  }

  override predicate isAdditionalTaintStep(TaintTracking::Predicate pred, TaintTracking::Predicate succ) {
    exists(CallExpr ma |
      ma.getTarget().getName() = "append" and
      ma.getTarget().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      TaintTracking::localTaintStep(pred.getAChild(), ma.getAnArgument()) and
      TaintTracking::localTaintStep(ma.getReceiver(), succ.getAChild())
    )
  }
}

from CommandInjectionConfig config, TaintTracking::PathNode source, TaintTracking::PathNode sink
where config.hasFlowPath(source, sink)
select sink, "Detected user input entering a method which executes a system command. This could result in a command injection vulnerability."