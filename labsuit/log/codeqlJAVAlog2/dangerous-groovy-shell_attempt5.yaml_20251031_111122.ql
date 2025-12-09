/**
 * @name Dangerous Groovy Shell Execution
 * @description A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @id python/dangerous-groovy-shell
 * @severity Warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.frameworks.Groovy

class GroovyShellSource extends TaintTracking::Source {
  GroovyShellSource() {
    exists(Variable v |
      v.getType() instanceof Class and
      (v.getType().getName() = "GroovyShell" or v.getType().getName() = "GroovyClassLoader") and
      v.getType().getModule().getName() = "groovy.lang" and
      this.asSource() = v.getAnAccess()
    )
  }
}

class GroovyShellEvalSink extends DataFlow::Node {
  GroovyShellEvalSink() {
    exists(Call ma |
      (ma.getCalleeName() = "parse" or 
       ma.getCalleeName() = "evaluate" or 
       ma.getCalleeName() = "parseClass") and
      ma.getCalleeType() instanceof Class and
      (ma.getCalleeType().getName() = "GroovyShell" or
       ma.getCalleeType().getName() = "GroovyClassLoader") and
      ma.getCalleeType().getModule().getName() = "groovy.lang" and
      this.asSink() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(string s | this.asSanitizer() = s)
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

from DataFlow::PathNode source, DataFlow::PathNode sink, GroovyShellConfig conf
where
  conf.hasFlowPath(source, sink)
select sink, "A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.", 
  source, "User input from $@", source.getNode(), "GroovyShell source"