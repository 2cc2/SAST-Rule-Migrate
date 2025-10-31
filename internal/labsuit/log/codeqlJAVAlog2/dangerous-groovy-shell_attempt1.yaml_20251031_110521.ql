/**
 * @name Dangerous Groovy Shell Evaluation
 * @description A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @id java/dangerous-groovy-shell
 * @severity Warning
 * @tags security
 *       cwe/CWE-94
 *       owasp/a03
 *       technology/groovy
 */

import java
import semmle.code.java.dataflow.TaintTracking

class GroovyShellSource extends DataFlow::Node {
  GroovyShellSource() {
    exists(MethodAccess ma | 
      (ma.getCallee().toString().matches("groovy.lang.GroovyShell%") or 
       ma.getCallee().toString().matches("groovy.lang.GroovyClassLoader%")) and
      this.asExpr() = ma.getQualifier()
    )
  }
}

class GroovyShellEvalSink extends DataFlow::Node {
  GroovyShellEvalSink() {
    exists(MethodAccess ma |
      (ma.getCallee().toString().matches("groovy.lang.GroovyShell.parse%") or
       ma.getCallee().toString().matches("groovy.lang.GroovyShell.evaluate%") or
       ma.getCallee().toString().matches("groovy.lang.GroovyShell.parseClass%") or
       ma.getCallee().toString().matches("groovy.lang.GroovyClassLoader.parse%") or
       ma.getCallee().toString().matches("groovy.lang.GroovyClassLoader.evaluate%") or
       ma.getCallee().toString().matches("groovy.lang.GroovyClassLoader.parseClass%")) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class GroovyShellSanitizer extends DataFlow::Node {
  GroovyShellSanitizer() {
    exists(Expr e | 
      (e instanceof StringLiteral or 
       (e instanceof MethodAccess and 
        e.getArgument(0).getValue().toString() = "..."))
    )
  }
}

class GroovyShellTaintFlowConfig extends TaintTracking::Configuration {
  GroovyShellTaintFlowConfig() { this = "GroovyShellTaintFlowConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof GroovyShellSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof GroovyShellEvalSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof GroovyShellSanitizer
  }
}

from GroovyShellTaintFlowConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential code injection vulnerability from dynamic Groovy shell evaluation."