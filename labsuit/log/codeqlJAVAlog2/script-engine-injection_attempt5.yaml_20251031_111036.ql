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
import DataFlow
import TaintTracking
import semmle.code.java.Methods
import semmle.code.java.frameworks.scripting.ScriptEngines

class UntrustedInput extends TaintTracking::Source {
  UntrustedInput() {
    exists(Parameter p |
      this.asParameter() = p and
      not exists(p.getAnAnnotation() |
        p.getAnAnnotation().getType().hasQualifiedName("javax.validation.constraints", "NotNull")
      )
    )
  }
}

class ScriptEngineEval extends TaintTracking::Sink {
  ScriptEngineEval() {
    exists(MethodAccess ma |
      ma = this.asExpr() and
      ma.getMethod().getName() = "eval" and
      ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("javax.script", "ScriptEngine")
    )
  }
}

class StringLiteralSanitizer extends TaintTracking::Sanitizer {
  StringLiteralSanitizer() {
    exists(StringLiteral sl |
      sl = this.asExpr() and
      regexpMatches("^\"[^\"]*\"$", sl.getValue())
    )
  }
}

class ScriptEngineInjectionConfig extends TaintTracking::Configuration {
  ScriptEngineInjectionConfig() { this = "ScriptEngineInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asParameter() instanceof UntrustedInput
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof ScriptEngineEval
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node.asExpr() instanceof StringLiteralSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    TaintTracking::localTaintStep(pred, succ) or
    DataFlow::FieldWriteStep(pred, succ)
  }
}

from ScriptEngineInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, 
  "Potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()'",
  source, "User input flows to script engine evaluation here"