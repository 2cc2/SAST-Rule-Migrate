/**
 * @name Command Injection in ProcessBuilder
 * @description A formatted or concatenated string was detected as input to a ProcessBuilder call.
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
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class ProcessBuilderSource extends DataFlow::Node {
  ProcessBuilderSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["command", "<init>"]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      (
        (
          ma.getMethod().hasName("command") and
          ma.getArgument(0).getType() instanceof TypeString and
          ma.getArgument(0).toString().regexpMatch("(sh|bash|ksh|csh|tcsh|zsh|cmd)")
        )
        or
        (
          ma.getMethod().hasName("<init>") and
          ma.getArgument(0).getType() instanceof TypeString and
          ma.getArgument(0).toString().regexpMatch("(sh|bash|ksh|csh|tcsh|zsh|cmd)")
        )
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class ProcessBuilderSink extends DataFlow::Node {
  ProcessBuilderSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["command", "<init>"]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      (
        (ma.getMethod().hasName("command") and ma.getArgument(0).toString() != "...") or
        (ma.getMethod().hasName("<init>") and ma.getArgument(0).toString() != "...")
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class CommandInjectionSanitizer extends DataFlow::Node {
  CommandInjectionSanitizer() {
    // String literals are safe
    exists(Literal l | l.getType() instanceof TypeString and this.asExpr() = l) or
    
    // Arrays.asList with literal arguments
    exists(MethodAccess ma |
      ma.getMethod().hasName("asList") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Arrays") and
      ma.getArgument(0).toString() = "..." and
      this.asExpr() = ma
    ) or
    
    // String array initialization with literals
    exists(ArrayInit ai |
      ai.getType().getElementType() instanceof TypeString and
      ai.toString() = "new String[]{...}" and
      this.asExpr() = ai
    )
  }
}

class CommandInjectionConfiguration extends TaintTracking::Configuration {
  CommandInjectionConfiguration() { this = "CommandInjectionConfiguration" }

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

from DataFlow::PathNode source, DataFlow::PathNode sink, CommandInjectionConfiguration conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "A formatted or concatenated string was detected as input to a ProcessBuilder call. " +
  "This is dangerous if a variable is controlled by user input and could result in a command injection. " +
  "Ensure your variables are not controlled by users or sufficiently sanitized."