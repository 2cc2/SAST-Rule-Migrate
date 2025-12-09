/**
 * @name Tainted system command
 * @description Detected user input entering a method which executes a system command. 
 * @kind problem
 * @id java/tainted-system-command
 * @severity error
 * @tags security
 *       cwe/cwe-78
 *       owasp/a01
 *       owasp/a03
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class RequestSource extends DataFlow::Node {
  RequestSource() {
    exists(Parameter p |
      p = this.asParameter() and
      not p.getType().toString().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)$") and
      p.getAnAnnotation().toString().matches("(RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)")
    )
  }
}

class StringConcat extends DataFlow::Node {
  StringConcat() {
    exists(BinaryAddExpr add | 
      add.getAnOperand() = this.asExpr() and
      add.getType() instanceof TypeString
    ) or
    exists(MethodAccess ma |
      (ma.getMethod().getName().matches("format") or 
       ma.getMethod().getName().matches("join") or
       ma.getMethod().getName().matches("concat")) and
      ma.getAnArgument() = this.asExpr()
    ) or
    exists(AssignExpr assign |
      assign.getRValue() = this.asExpr() and
      assign.getType() instanceof TypeString
    )
  }
}

class CommandSink extends DataFlow::Node {
  CommandSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getName().matches("exec") or
       ma.getMethod().getName().matches("load") or
       ma.getMethod().getName().matches("loadLibrary") or
       ma.getMethod().getName().matches("command") or
       ma.getMethod().getName().matches("start")) and
      (ma.getQualifier().getType().toString().matches("ProcessBuilder") or
       ma.getQualifier().getType().toString().matches("Runtime"))
    )
  }
}

class ArgumentValidator extends DataFlow::Node {
  ArgumentValidator() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("validateCommand") and
      ma.getDeclaringType().toString().matches("CommandValidationUtils")
    )
  }
}

class TaintedCommandConfig extends TaintTracking::Configuration {
  TaintedCommandConfig() { this = "TaintedCommandConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(RequestSource rs | rs = source) or
    exists(StringConcat sc | sc = source)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(CommandSink cs | cs = sink)
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(ArgumentValidator av | av = node)
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("append") and
      ma.getQualifier().getType().toString().matches("StringBuilder") and
      pred.asExpr() = ma.getAnArgument() and
      succ.asExpr() = ma.getQualifier()
    )
  }
}

from TaintedCommandConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential command injection vulnerability from user input to system command execution."