/*
 * @name Dangerous Groovy Shell Evaluation
 * @description A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.0
 * @precision high
 * @id java/dangerous-groovy-shell
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class GroovyShellSource extends LocalVariable {
  GroovyShellSource() {
    this.getType().hasQualifiedName("groovy.lang", "GroovyShell") or
    this.getType().hasQualifiedName("groovy.lang", "GroovyClassLoader")
  }
}

class DangerousEvaluationSink extends MethodAccess {
  DangerousEvaluationSink() {
    this.getMethod().hasName(["parse", "evaluate", "parseClass"]) and
    (this.getMethod().getDeclaringType().matches("groovy.lang.GroovyShell") or
     this.getMethod().getDeclaringType().matches("groovy.lang.GroovyClassLoader"))
  }

  int getTaintedArgumentIndex() { result = 0 }
}

class GroovyShellLiteralSanitizer extends Literal {
  GroovyShellLiteralSanitizer() {
    this.getType().hasQualifiedName("java.lang", "String")
  }
}

class FixedStringSanitizer extends MethodAccess {
  FixedStringSanitizer() {
    exists(Literal lit |
      this.getArgument(0) = lit and
      lit.getStringValue() = "..."
    )
  }
}

class GroovyShellTaintTrackingConfig extends TaintTracking::Configuration {
  GroovyShellTaintTrackingConfig() { this = "GroovyShellTaintTrackingConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof GroovyShellSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DangerousEvaluationSink des |
      des.getArgument(des.getTaintedArgumentIndex()) = sink.asExpr()
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node.asExpr() instanceof GroovyShellLiteralSanitizer or
    node.asExpr() instanceof FixedStringSanitizer
  }
}

from DataFlow::Node source, DataFlow::Node sink
where any(GroovyShellTaintTrackingConfig c).hasFlow(source, sink)
select sink, "A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."