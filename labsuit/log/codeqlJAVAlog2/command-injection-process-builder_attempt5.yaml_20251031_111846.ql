/**
 * @name Command Injection via ProcessBuilder
 * @description Detects command injection vulnerabilities in ProcessBuilder calls
 * @kind path-problem
 * @id java/command-injection-process-builder
 * @severity ERROR
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class ProcessBuilderCommandSource extends TaintTracking::Source {
  ProcessBuilderCommandSource() {
    exists(Method m, MethodAccess ma |
      (
        m.hasName("command") and
        m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
        ma.getMethod() = m and
        (
          // First variant: command(String...)
          ma.getArgument(0).toString().matches("sh|bash|ksh|csh|tcsh|zsh|cmd") and
          this.asExpr() = ma.getArgument(0)
        )
      )
      or
      (
        m.hasName("<init>") and
        m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
        ma.getMethod() = m and
        ma.getArgument(0).toString().matches("sh|bash|ksh|csh|tcsh|zsh|cmd") and
        this.asExpr() = ma.getArgument(0)
      )
    )
  }
}

class ProcessBuilderSink extends TaintTracking::Sink {
  ProcessBuilderSink() {
    exists(Method m, MethodAccess ma |
      (
        m.hasName("command") and
        m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
        ma.getMethod() = m and
        this.asExpr() = ma.getAnArgument() and
        not ma.getArgument(0).toString() = "..."
      )
      or
      (
        m.hasName("<init>") and
        m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
        ma.getMethod() = m and
        this.asExpr() = ma.getAnArgument() and
        not ma.getArgument(0).toString() = "..."
      )
    )
  }
}

class SafeStringLiteral extends TaintTracking::Sanitizer {
  SafeStringLiteral() {
    this.asExpr() instanceof StringLiteral
  }
}

class SafeArrayInit extends TaintTracking::Sanitizer {
  SafeArrayInit() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("asList") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Arrays") and
      this.asExpr() = ma and
      ma.getArgument(0).toString() = "..."
    )
  }
}

class SafeStringArray extends TaintTracking::Sanitizer {
  SafeStringArray() {
    exists(ArrayInit ai |
      this.asExpr() = ai and
      ai.toString() = "..."
    )
  }
}

class ProcessBuilderTaintConfig extends TaintTracking::Configuration {
  ProcessBuilderTaintConfig() { this = "ProcessBuilderTaintConfig" }

  override predicate isSource(TaintTracking::Source source) {
    source instanceof ProcessBuilderCommandSource
  }

  override predicate isSink(TaintTracking::Sink sink) {
    sink instanceof ProcessBuilderSink
  }

  override predicate isSanitizer(TaintTracking::Sanitizer sanitizer) {
    sanitizer instanceof SafeStringLiteral or
    sanitizer instanceof SafeArrayInit or
    sanitizer instanceof SafeStringArray
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, ProcessBuilderTaintConfig config
where config.hasFlowPath(source, sink)
select sink, "A formatted or concatenated string was detected as input to a ProcessBuilder call. " +
  "This is dangerous if a variable is controlled by user input and could result in a command injection. " +
  "Ensure your variables are not controlled by users or sufficiently sanitized."