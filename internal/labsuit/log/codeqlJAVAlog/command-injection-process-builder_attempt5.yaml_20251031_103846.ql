/**
 * @name Command Injection in ProcessBuilder
 * @description Detects potentially unsafe command execution via ProcessBuilder where
 *              user-controlled input may be used without proper sanitization.
 * @id command-injection-process-builder
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-078
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class ProcessBuilderSource extends DataFlow::ExprNode {
  ProcessBuilderSource() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "command" and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder")) or
      (ma.getMethod().getName() = ["<init>"] and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder"))
    |
      this.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isShellCommand() {
    exists(string shellPattern |
      shellPattern = "%sh%" or shellPattern = "%bash%" or shellPattern = "%ksh%" or
      shellPattern = "%csh%" or shellPattern = "%tcsh%" or shellPattern = "%zsh%" or shellPattern = "cmd"
    |
      this.asExpr().toString().matches(shellPattern)
    )
  }
}

class ProcessBuilderSink extends DataFlow::ExprNode {
  ProcessBuilderSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "command" and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder")) or
      (ma.getMethod().getName() = ["<init>"] and ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder"))
    |
      this.asExpr() = ma.getAnArgument() 
    )
  }
}

class CommandInjectionSanitizer extends DataFlow::Node {
  CommandInjectionSanitizer() {
    // String literal sanitizer
    exists(Literal lit | this.asExpr() = lit.getExpr() and lit.isStringLiteral()) or
    // Arrays.asList sanitizer
    exists(MethodAccess ma |
      ma.getMethod().getName() = "asList" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Arrays")
    |
      this.asExpr() = ma
    ) or
    // String array sanitizer
    exists(ArrayCreation ac |
      ac.getType().(ArrayType).getElementType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ac
    )
  }
}

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ProcessBuilderSource and
    source.(ProcessBuilderSource).isShellCommand()
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ProcessBuilderSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof CommandInjectionSanitizer
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, CommandInjectionConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "A formatted or concatenated string was detected as input to a ProcessBuilder call. " +
  "This is dangerous if a variable is controlled by user input and could result in " +
  "a command injection. Ensure your variables are not controlled by users or " +
  "sufficiently sanitized."