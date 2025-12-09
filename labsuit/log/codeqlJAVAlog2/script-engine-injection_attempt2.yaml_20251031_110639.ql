/**
 * @name Script Engine Injection
 * @description Detected potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()', otherwise, this is a code injection vulnerability.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id java/script-engine-injection
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
    exists(Parameter p |
      not p.getAnAnnotation() instanceof Annotation and
      result = p.getVariable()
    )
  }
}

class ScriptEngineEval extends TaintTracking::Sink {
  ScriptEngineEval() {
    exists(MethodCall evalCall |
      evalCall.getMethod().hasName("eval") and
      evalCall.getQualifier().getType().getASupertype*().hasQualifiedName("javax.script", "ScriptEngine") and
      this = evalCall.getArgument(0)
    )
  }
}

class StringLiteral extends TaintTracking::Sanitizer {
  StringLiteral() {
    exists(stringLiteral l |
      l instanceof StringLiteral and
      this = l
    )
  }
}

class ScriptEngineInjectionFlowConfig extends TaintTracking::Configuration {
  ScriptEngineInjectionFlowConfig() { 
    this = "ScriptEngineInjectionFlowConfig" 
  }

  override predicate isSource(DataFlow::Node source) { 
    source.asParameter() instanceof UntrustedInput 
  }

  override predicate isSink(DataFlow::Node sink) { 
    sink.asExpr() instanceof ScriptEngineEval 
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) { 
    sanitizer.asExpr() instanceof StringLiteral 
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    TaintTracking::localTaintStep(pred, succ) or
    exists(Field f, Assignment a |
      a.getLeftOperand() = f and
      pred.asExpr() = a.getRightOperand() and
      succ.asExpr() = f
    )
  }
}

from ScriptEngineInjectionFlowConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()'."