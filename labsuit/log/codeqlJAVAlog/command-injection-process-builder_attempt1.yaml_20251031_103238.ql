/**
 * @name Command Injection in ProcessBuilder
 * @description A formatted or concatenated string was detected as input to a ProcessBuilder call.
 *              This is dangerous if a variable is controlled by user input and could result in a command injection.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/command-injection-process-builder
 * @tags security
 *       external/cwe/cwe-078
 *       owasp-a01:2017/injection
 *       owasp-a03:2021/injection
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class ProcessBuilderSource extends DataFlow::Node {
  ProcessBuilderSource() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "command" or ma.getMethod().isConstructor()) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      ma.getArgument(0) = this.asExpr() and
      ma.getArgument(0).toString().regexpMatch("/(sh|bash|ksh|csh|tcsh|zsh)/|^cmd$")
    )
  }
}

class ProcessBuilderSink extends DataFlow::Node {
  ProcessBuilderSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "command" or ma.getMethod().isConstructor()) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      ma.getArgument(0) = this.asExpr() and
      ma.getArgument(0).toString() != "..."
    )
  }
}

class CommandInjectionSanitizer extends DataFlow::Node {
  CommandInjectionSanitizer() {
    // String literal sanitizer
    exists(Literal l | l = this.asExpr() and l.getType().hasName("String")) or
    // Arrays.asList sanitizer
    exists(MethodAccess ma |
      ma.getMethod().getName() = "asList" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Arrays") and
      ma.getArgument(0).toString() = "..." and
      this.asExpr() = ma
    ) or
    // String array literal sanitizer
    exists(ArrayInit ai |
      ai.getElementType().hasName("String") and
      this.asExpr() = ai and
      ai.toString() = "new String[]{...}"
    )
  }
}

class ProcessBuilderTaintTrackingConfig extends TaintTracking::Configuration {
  ProcessBuilderTaintTrackingConfig() { this = "ProcessBuilderCommandInjection" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ProcessBuilderSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ProcessBuilderSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof CommandInjectionSanitizer
  }
}

from ProcessBuilderTaintTrackingConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential command injection vulnerability in ProcessBuilder. User input flows into command execution.",
  source, "User input source",
  sink, "ProcessBuilder command execution"