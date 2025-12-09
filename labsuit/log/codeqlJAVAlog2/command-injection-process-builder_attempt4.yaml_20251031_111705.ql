import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class ProcessBuilderCommandSource extends DataFlow::Node {
  ProcessBuilderCommandSource() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getName() = "command" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
        (
          this.asParameter() = ma.getParameter(0) or
          exists(Expr e | e = ma.getArgument(0) and this.asExpr() = e)
        ) and
        ma.getArgument(0).toString().matches("sh|bash|ksh|csh|tcsh|zsh|cmd")
      )
      or
      (
        ma.getMethod().getName() = "<init>" and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
        this.asParameter() = ma.getParameter(0) and
        ma.getArgument(0).toString().matches("sh|bash|ksh|csh|tcsh|zsh|cmd")
      )
    )
  }
}

class ProcessBuilderSink extends DataFlow::Node {
  ProcessBuilderSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "command" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      (
        this.asParameter() = ma.getParameter(_) or
        exists(Expr e | e = ma.getArgument(0) and this.asExpr() = e)
      ) and
      not ma.getArgument(0).toString() = "..."
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().getName() = "<init>" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      this.asParameter() = ma.getParameter(_) and
      not ma.getArgument(0).toString() = "..."
    )
  }
}

class SafeStringLiteral extends DataFlow::Node {
  SafeStringLiteral() {
    exists(StringLiteral sl | this.asExpr() = sl)
  }
}

class SafeArrayInit extends DataFlow::Node {
  SafeArrayInit() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "asList" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.util", "Arrays") and
      this.asParameter() = ma.getParameter(_) and
      ma.getArgument(0).toString() = "..."
    )
  }
}

class SafeStringArray extends DataFlow::Node {
  SafeStringArray() {
    exists(ArrayCreationExpr ace |
      this.asExpr() = ace and
      exists(ace.getInitializer() |
        ace.getInitializer().toString() = "..."
      )
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

from DataFlow::Node source, DataFlow::Node sink, ProcessBuilderTaintConfig config
where config.hasFlow(source, sink)
select sink, "A formatted or concatenated string was detected as input to a ProcessBuilder call. " +
  "This is dangerous if a variable is controlled by user input and could result in a command injection. " +
  "Ensure your variables are not controlled by users or sufficiently sanitized."