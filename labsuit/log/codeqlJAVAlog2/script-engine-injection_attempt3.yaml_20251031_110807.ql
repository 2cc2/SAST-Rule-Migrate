/**
 * @name Script Engine Injection
 * @description Detected potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()'
 * @id script-engine-injection
 * @kind path-problem
 * @severity Warning
 * @tags security
 *       external/cwe/cwe-094
 *       owasp-a3
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.scripting.ScriptEngine
import semmle.code.java.Annotation

class UntrustedInput extends TaintTracking::Source {
  UntrustedInput() {
    exists(MethodParameter p |
      p = this |
      not p.getType().hasAnnotation("javax.validation.constraints.NotNull")
    )
  }
}

class ScriptEngineEval extends TaintTracking::Sink {
  ScriptEngineEval() {
    exists(MethodCall mc |
      mc = this |
      mc.getCallee().getName() = "eval" and
      mc.getCallee().getDeclaringType().getASupertype*().hasQualifiedName("javax.script", "ScriptEngine")
    )
  }
}

class StringLiteral extends TaintTracking::Sanitizer {
  StringLiteral() {
    exists(Literal l |
      l = this |
      regexpMatch("^\"[^\"]*\""$, l.toString())
    )
  }
}

class ScriptEngineInjectionConfig extends TaintTracking::Configuration {
  ScriptEngineInjectionConfig() { this = "ScriptEngineInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UntrustedInput
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ScriptEngineEval
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof StringLiteral
  }

  override predicate isSanitizer(DataFlow::Node node, DataFlow::Node sink) {
    node instanceof StringLiteral
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Propagate taint through arguments and field assignments
    TaintTracking::localTaintStep(pred, succ) or
    DataFlow::fieldWriteStep(pred, succ)
  }
}

from ScriptEngineInjectionConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, 
  "Potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()'",
  source, "User input flows to script engine evaluation here"