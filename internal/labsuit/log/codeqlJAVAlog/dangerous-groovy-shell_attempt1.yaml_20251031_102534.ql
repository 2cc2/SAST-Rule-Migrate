/**
 * @name Dangerous Groovy Shell Usage
 * @description Expression built with dynamic value. Verify source to avoid unfiltered values in risky code evaluation.
 * @kind path-problem
 * @problem.severity warning
 * @id java/dangerous-groovy-shell
 * @tags security
 *       cwe:94
 *       owasp:a03
 *       technology:groovy
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class GroovyShellSource extends DataFlow::Node {
  GroovyShellSource() {
    exists(LocalVariable v | 
      v.getType().hasName("groovy.lang.GroovyShell") or
      v.getType().hasName("groovy.lang.GroovyClassLoader") |
      this.asExpr() = v
    )
  }
}

class DangerousEvaluationSink extends DataFlow::Node {
  DangerousEvaluationSink() {
    exists(MethodAccess m |
      (m.getMethod().getName() = "parse" or
       m.getMethod().getName() = "evaluate" or
       m.getMethod().getName() = "parseClass") and
      (m.getQualifier().getType().hasName("groovy.lang.GroovyShell") or
       m.getQualifier().getType().hasName("groovy.lang.GroovyClassLoader")) and
      this.asExpr() = m.getArgument(0)
    )
  }
}

class GroovyShellLiteralSanitizer extends DataFlow::Node {
  GroovyShellLiteralSanitizer() {
    exists(Literal l |
      l.getType().hasName("java.lang.String") and
      this.asExpr() = l
    )
  }
}

class FixedStringSanitizer extends DataFlow::Node {
  FixedStringSanitizer() {
    exists(MethodAccess m |
      (m.getMethod().getName() = "parse" or
       m.getMethod().getName() = "evaluate" or
       m.getMethod().getName() = "parseClass") and
      (m.getQualifier().getType().hasName("groovy.lang.GroovyShell") or
       m.getQualifier().getType().hasName("groovy.lang.GroovyClassLoader")) and
      m.getArgument(0).(StringLiteral).getValue() = "..." and
      this.asExpr() = m.getArgument(0)
    )
  }
}

class GroovyShellTaintConfig extends TaintTracking::Configuration {
  GroovyShellTaintConfig() { this = "GroovyShellTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof GroovyShellSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof DangerousEvaluationSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof GroovyShellLiteralSanitizer or
    node instanceof FixedStringSanitizer
  }

  override predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess m |
      (succ.asExpr() = m.getArgument(0) and
       pred.asExpr() = m.getQualifier()) and
      (m.getMethod().getName() = "parse" or
       m.getMethod().getName() = "evaluate" or
       m.getMethod().getName() = "parseClass")
    )
  }
}

from GroovyShellTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), "A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.",
  source.getNode(), "User-provided value here"