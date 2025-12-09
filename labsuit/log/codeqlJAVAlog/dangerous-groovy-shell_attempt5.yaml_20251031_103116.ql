/** 
 * @name Dangerous Groovy Shell Usage
 * @description Detects when a GroovyShell or GroovyClassLoader is created with unvalidated input
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @id java/groovy-shell-injection
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
    this.getType().hasQualifiedName("java.lang", "String")
  }
}

class FixedStringSanitizer extends MethodAccess {
  FixedStringSanitizer() {
    this.getMethod() instanceof DangerousEvaluationSink and
    exists(LiteralExpr arg | arg = this.getArgument(0) and arg.getStringValue() = "...")
  }
}

class DangerousGroovyShellConfig extends TaintTracking::Configuration {
  DangerousGroovyShellConfig() { this = "DangerousGroovyShellConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(LocalVariableDecl decl |
      decl.getType() instanceof GroovyShellSource and
      source.asExpr() = decl.getVariable().getInitializer()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess call |
      call.getMethod() instanceof DangerousEvaluationSink and
      sink.asExpr() = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() instanceof GroovyShellLiteralSanitizer or
    sanitizer.asExpr() instanceof FixedStringSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess call |
      call.getMethod() instanceof DangerousEvaluationSink and
      pred.asExpr() = call.getQualifier() and
      succ.asExpr() = call
    )
  }
}

from DangerousGroovyShellConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "A expression is built with a dynamic value. The source of the value(s) should be checked.",
  source.getNode(), "user input"