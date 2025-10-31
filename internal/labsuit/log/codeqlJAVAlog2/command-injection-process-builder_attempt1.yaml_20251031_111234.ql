/**
 * @name Command Injection in ProcessBuilder
 * @description A formatted or concatenated string was detected as input to a ProcessBuilder call.
 *              This is dangerous if a variable is controlled by user input and could result 
 *              in a command injection.
 * @kind path-problem
 * @problem.severity error
 * @id java/command-injection-process-builder
 * @tags security
 *       cwe/CWE-78
 *       owasp/a01:2017
 *       owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class ProcessBuilderCommandSource extends DataFlow::Node {
  ProcessBuilderCommandSource() {
    exists(MethodAccess ma | 
      (ma.getMethod().getName() = "command" or ma.getMethod().isConstructor()) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      ma.getArgument(0) = this.asExpr() and
      (
        this.asExpr().toString().regexpMatch("^(sh|bash|ksh|csh|tcsh|zsh)|^cmd$")
      )
    )
  }
}

class ProcessBuilderSink extends DataFlow::Node {
  ProcessBuilderSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "command" or ma.getMethod().isConstructor()) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      ma.getAnArgument() = this.asExpr() and
      not this.asExpr().toString() = "..."
    )
  }
}

class SafeStringLiteral extends DataFlow::Node {
  SafeStringLiteral() {
    exists(Literal l | l = this.asExpr() and l.getType().hasName("String"))
  }
}

class SafeArrayInit extends DataFlow::Node {
  SafeArrayInit() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "asList" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Arrays") and
      ma.getArgument(0).toString() = "..." and
      this.asExpr() = ma
    )
  }
}

class SafeStringArray extends DataFlow::Node {
  SafeStringArray() {
    exists(ArrayCreation ac |
      ac.getElementType().hasName("String") and
      ac.getInitializer().toString() = "..." and
      this.asExpr() = ac
    )
  }
}

class ProcessBuilderTaintConfig extends TaintTracking::Configuration {
  ProcessBuilderTaintConfig() { this = "ProcessBuilderTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ProcessBuilderCommandSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ProcessBuilderSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof SafeStringLiteral or
    node instanceof SafeArrayInit or
    node instanceof SafeStringArray
  }
}

from ProcessBuilderTaintConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "A formatted or concatenated string was detected as input to a ProcessBuilder call. " +
  "This is dangerous if a variable is controlled by user input and could result in a command injection. " +
  "Ensure your variables are not controlled by users or sufficiently sanitized."