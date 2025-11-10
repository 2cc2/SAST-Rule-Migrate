/**
 * @name Tainted System Command
 * @description Detects user input entering a method which executes a system command,
 *              which could result in a command injection vulnerability.
 * @kind path-problem
 * @problem.severity error
 * @id java/tainted-system-command
 * @tags security
 *       external/cwe/cwe-78
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class CommandSource extends DataFlow::Node {
  CommandSource() {
    exists(Parameter p | this.asParameter() = p) or
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "concat" and
       ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")) or
      exists(Method m |
        m.getName().matches("format|join") and
        m.getDeclaringType().hasQualifiedName("java.lang", "String") and
        ma.getMethod() = m
      )
      and this.asExpr() = ma.getAnArgument()
    )
  }
}

class CommandSink extends DataFlow::Node {
  CommandSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("exec|loadLibrary|load") and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder")
      ) and
      this.asExpr() = ma.getAnArgument()
    ) or
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder") and
      this.asExpr() = cc.getAnArgument()
    )
  }
}

class CommandConfig extends TaintTracking::Configuration {
  CommandConfig() { this = "CommandConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof CommandSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof CommandSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) { none() }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "append" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      pred.asExpr() = ma.getAnArgument() and
      succ.asExpr() = ma.getQualifier()
    )
  }
}

from CommandConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected user input entering a method which executes a system command. " +
  "This could result in a command injection vulnerability. " +
  "Instead, use ProcessBuilder with separated arguments."