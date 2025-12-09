/**
 * @name Dangerous Groovy Shell Evaluation
 * @description Detects unsafe Groovy shell evaluations where user input could lead to code injection
 * @kind path-problem
 * @problem.severity warning
 * @id java/dangerous-groovy-shell
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class GroovyShellSource extends RefType {
  GroovyShellSource() {
    this.hasQualifiedName("groovy.lang", "GroovyShell") or
    this.hasQualifiedName("groovy.lang", "GroovyClassLoader")
  }
}

class DangerousEvaluationSink extends Method {
  DangerousEvaluationSink() {
    this.getDeclaringType() instanceof GroovyShellSource and
    this.hasName(["parse", "evaluate", "parseClass"]) and
    this.getNumberOfParameters() > 0
  }
}

class GroovyShellLiteralSanitizer extends LiteralExpr {
  GroovyShellLiteralSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod() instanceof DangerousEvaluationSink and
      ma.getArgument(0) = this and
      this.getType().hasName("java.lang.String")
    )
  }
}

class FixedStringSanitizer extends MethodAccess {
  FixedStringSanitizer() {
    this.getMethod() instanceof DangerousEvaluationSink and
    exists(LiteralExpr lit |
      this.getArgument(0).asValue() = lit and
      lit.getValue().toString().matches("...")
    )
  }
}

class DangerousGroovyShellConfig extends TaintTracking::Configuration {
  DangerousGroovyShellConfig() { this = "DangerousGroovyShellConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(LocalVariableDecl var |
      var.getType() instanceof GroovyShellSource and
      source.asParameter() = var.getInitializer().asValue()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DangerousEvaluationSink ma |
      ma.getArgument(0) = sink.asValue()
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asValue() instanceof GroovyShellLiteralSanitizer or
    exists(FixedStringSanitizer fma | sanitizer.asValue() = fma.getArgument(0))
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma |
      ma.getMethod() instanceof DangerousEvaluationSink and
      ma.getQualifier() = node1.asValue() and
      node2.asValue() = ma
    )
  }
}

from DangerousGroovyShellConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation."