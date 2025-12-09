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
import DataFlow::PathGraph
import DataFlow::TaintTracking

class GroovyShellSource extends DataFlow::Node {
  GroovyShellSource() {
    exists(Variable v | 
      v.getType().hasName(["groovy.lang.GroovyShell", "groovy.lang.GroovyClassLoader"]) and
      this.asExpr() = v
    )
  }
}

class GroovyShellEvalSink extends DataFlow::Node {
  GroovyShellEvalSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName(["parse", "evaluate", "parseClass"]) and
      ma.getMethod().getDeclaringType().hasName(["groovy.lang.GroovyShell", "groovy.lang.GroovyClassLoader"]) and
      ma.getArgument(0) = this.asExpr()
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    this.asExpr() instanceof StringLiteral
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
  source, "User input from $@", source, "GroovyShell source"