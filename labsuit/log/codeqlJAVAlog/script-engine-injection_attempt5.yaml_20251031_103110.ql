/**
 * @name Script Engine Injection
 * @description Detected potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()'
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id java/script-engine-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class ScriptEngineEvalMethod extends Method {
  ScriptEngineEvalMethod() {
    this.getDeclaringType().getQualifiedName() = "javax.script.ScriptEngine" and
    this.getName() = "eval"
  }
}

class UntrustedInputSource extends DataFlow::Node {
  UntrustedInputSource() {
    exists(MethodParameter p |
      p = this.asParameter() and
      not p.getAnAnnotation().getType().hasQualifiedName("javax.validation.constraints", "NotNull")
    )
  }
}

class ScriptEngineSink extends DataFlow::Node {
  ScriptEngineSink() {
    exists(MethodCall call |
      call = this.asExpr() and
      call.getCallee() instanceof ScriptEngineEvalMethod and
      this.asExpr() = call.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    this.asExpr() instanceof StringLiteral
  }
}

class ScriptEngineTaintConfig extends TaintTracking::Configuration {
  ScriptEngineTaintConfig() { this = "ScriptEngineTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UntrustedInputSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ScriptEngineSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof StringLiteralSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodCall call |
      call.getArgument(0) = node1.asExpr() and
      call.getAnArgument() = node2.asParameter()
    ) or
    exists(FieldAccess fa |
      fa.getRhs() = node1.asExpr() and
      fa.getLhs() = node2.asExpr()
    )
  }
}

from ScriptEngineTaintConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()'."