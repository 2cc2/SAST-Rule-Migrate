/**
 * @name Tainted system command
 * @description Detected user input entering a method which executes a system command.
 * @kind problem
 * @problem.severity error
 * @id java/tainted-system-command
 * @tags security
 *       cwe/cwe-78
 *       owasp/a01:2017
 *       owasp/a03:2021
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class RequestSource extends DataFlow::Node {
  RequestSource() {
    exists(MethodParameter p |
      p = this.asParameter() and
      not p.getType().hasName(["Integer", "Long", "Float", "Double", "Char", "Boolean", "int", "long", "float", "double", "char", "boolean"]) and
      p.getAnAnnotation().getType().getName().matches("%(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)%")
    )
  }
}

class StringConcat extends DataFlow::Node {
  StringConcat() {
    exists(DataFlow::Node source |
      exists(Call c |
        (
          (c instanceof AddExpr and (c.getLeftOperand() = source or c.getRightOperand() = source)) or
          (c instanceof MethodAccess and c.getMethod().getName() = "format" and c.getArgument(_) = source) or
          (c instanceof MethodAccess and c.getMethod().getName() = "join" and c.getArgument(_) = source) or
          (c instanceof MethodAccess and c.getMethod().getName() = "concat" and c.getQualifier() = source) or
          (c instanceof CompoundAssignment and c.getLeftOperand() = source)
        ) and
        source instanceof RequestSource
      ) and
      this.asExpr() = c
    )
  }
}

class CommandSink extends DataFlow::Node {
  CommandSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getName() = "exec" or
        ma.getMethod().getName() = "load" or
        ma.getMethod().getName() = "loadLibrary" or
        (ma.getMethod().getName() = "command" and ma.getQualifier().getType().hasName("ProcessBuilder")) or
        (ma.getMethod().getName() = "start" and ma.getQualifier().getType().hasName("ProcessBuilder"))
      ) and
      this.asExpr() = ma
    )
  }
}

class ArgumentValidator extends DataFlow::BarrierGuard {
  ArgumentValidator() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "validateCommand" and
      ma.getQualifier().getType().hasName("CommandValidationUtils") and
      this.asExpr() = ma
    )
  }
}

class StringBuilderConcat extends DataFlow::AdditionalTaintStep {
  override predicate step(DataFlow::Node src, DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "append" and
      ma.getQualifier().getType().hasName("StringBuilder") and
      src.asExpr() = ma.getAnArgument() and
      sink.asExpr() = ma
    )
  }
}

class TaintedCommandConfig extends TaintTracking::Configuration {
  TaintedCommandConfig() { this = "TaintedCommandConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RequestSource or source instanceof StringConcat
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandSink
  }

  override predicate isBarrier(DataFlow::Node barrier) {
    barrier instanceof ArgumentValidator
  }

  override predicate isAdditionalTaintStep(DataFlow::Node src, DataFlow::Node sink) {
    StringBuilderConcat().step(src, sink)
  }
}

from DataFlow::Node source, DataFlow::Node sink, TaintedCommandConfig config
where config.hasFlow(source, sink)
select sink, "Detected user input entering a method which executes a system command."