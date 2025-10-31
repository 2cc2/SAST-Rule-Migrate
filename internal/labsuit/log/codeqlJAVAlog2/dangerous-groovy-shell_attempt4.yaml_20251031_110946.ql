/**
 * @name Dangerous Groovy Shell Execution
 * @description A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @id java/dangerous-groovy-shell
 * @severity Warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Groovy

class GroovyShellSource extends TaintTracking::RemoteFlowSource {
  GroovyShellSource() {
    exists(LocalVariable v | 
      v.getType() instanceof RefType and
      (v.getType().getName() = "GroovyShell" or v.getType().getName() = "GroovyClassLoader") and
      v.getType().getNamespace().getName() = "groovy.lang" and
      this.asExpr() = v.getAnAccess()
    )
  }
}

class GroovyShellEvalSink extends DataFlow::Node {
  GroovyShellEvalSink() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "parse" or 
       ma.getMethod().getName() = "evaluate" or 
       ma.getMethod().getName() = "parseClass") and
      ma.getMethod().getDeclaringType() instanceof RefType and
      (ma.getMethod().getDeclaringType().getName() = "GroovyShell" or
       ma.getMethod().getDeclaringType().getName() = "GroovyClassLoader") and
      ma.getMethod().getDeclaringType().getNamespace().getName() = "groovy.lang" and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    this.getStringValue() != "" // Simplified representation of string literal
  }
}

class GroovyShellConfig extends TaintTracking::Configuration {
  GroovyShellConfig() { this = "GroovyShellConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof GroovyShellSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof GroovyShellEvalSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof StringLiteralSanitizer
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  exists(GroovyShellConfig conf |
    conf.hasFlowPath(source, sink)
  )
select sink, "A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.", 
  source, "User input from $@", source.getNode(), "GroovyShell source"