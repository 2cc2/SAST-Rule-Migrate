/**
 * @name Command injection via ProcessBuilder
 * @description Detects unsafe inputs to ProcessBuilder that could lead to command injection
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/command-injection-process-builder
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */
import java
import DataFlow::PathGraph
import semmle.code.java.dataflow.TaintTracking

class ProcessBuilderSource extends DataFlow::Node {
  ProcessBuilderSource() {
    exists(Method m |
      m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      (m.hasName("command") or m.getName() = "<init>") and
      (
        this.asParameter() = m.getParameter(0) or
        this.asExpr().(MethodAccess).getMethod() = m and
        this.asExpr().getArgument(0).getType() instanceof string and
        (
          this.asExpr().getArgument(0).toString().matches("%sh|bash|ksh|csh|tcsh|zsh%") or
          this.asExpr().getArgument(0).toString() = "cmd"
        )
      )
    )
  }
}

class ProcessBuilderSink extends DataFlow::Node {
  ProcessBuilderSink() {
    exists(Method m |
      m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      (m.hasName("command") or m.getName() = "<init>") and
      this.asExpr().(MethodAccess).getMethod() = m and
      this.asExpr().toString() != "..."
    )
  }
}

class CommandInjectionSanitizer extends DataFlow::Node {
  CommandInjectionSanitizer() {
    // String literals
    this.asExpr() instanceof LiteralExpr or
    // Arrays.asList() call
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Arrays") and
      ma.getMethod().hasName("asList") and
      this.asExpr() = ma.getArgument(0) and
      ma.getArgument(0).toString() = "..."
    ) or
    // String array creation
    exists(ArrayCreation ac |
      ac.getType() instanceof Array and
      ac.getType().getElementType() instanceof string and
      this.asExpr() = ac and
      ac.toString() = "new String[]{...}"
    )
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
}

from CommandInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "A formatted or concatenated string was detected as input to a ProcessBuilder call. " +
  "This is dangerous if a variable is controlled by user input and could result in a command injection. " +
  "Ensure your variables are not controlled by users or sufficiently sanitized."