/**
 * @name Command injection in ProcessBuilder
 * @description Detects command injection vulnerabilities in ProcessBuilder calls
 * @kind path-problem
 * @problem.severity error
 * @id java/command-injection-process-builder
 * @tags security
 *       external/cwe/cwe-078
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import DataFlow::PathGraph
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class ProcessBuilderSource extends DataFlow::Node {
  ProcessBuilderSource() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "command" and
       ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
       ma.getArgument(0).getText().regexpMatch("^(sh|bash|ksh|csh|tcsh|zsh|cmd)$"))
      or
      (ma.getMethod().getName() = "<init>" and
       ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
       ma.getArgument(0).getText().regexpMatch("^(sh|bash|ksh|csh|tcsh|zsh|cmd)$"))
      and
      this.asExpr() = ma
    )
  }
}

class ProcessBuilderSink extends DataFlow::Node {
  ProcessBuilderSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "command" or
       ma.getMethod().getName() = "<init>") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      ma.getArgument(0).getText() != "..." and
      this.asExpr() = ma
    )
  }
}

class CommandInjectionSanitizer extends DataFlow::Node {
  CommandInjectionSanitizer() {
    // String literals
    exists(Literal lit | lit.isStringLiteral() and this.asExpr() = lit)
    or
    // Arrays.asList(...)
    exists(MethodAccess ma |
      ma.getMethod().getName() = "asList" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Arrays") and
      ma.getArgument(0).getText() = "..." and
      this.asExpr() = ma
    )
    or
    // new String[]{...}
    exists(ArrayInit ai | ai.getArrayType().toString() = "String[]" and this.asExpr() = ai)
  }
}

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ProcessBuilderSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ProcessBuilderSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof CommandInjectionSanitizer
  }

  override predicate isSanitizer(DataFlow::Node node, boolean isSink) {
    node instanceof CommandInjectionSanitizer
  }
}

from CommandInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "A formatted or concatenated string was detected as input to a ProcessBuilder call. This could result in command injection."