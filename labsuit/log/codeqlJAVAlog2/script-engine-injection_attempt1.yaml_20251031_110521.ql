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
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.scripting.ScriptEngine

class UntrustedInput extends TaintTracking::Source {
  UntrustedInput() {
    exists(MethodParameter p |
      p.getAnAnnotation() instanceof NotNullAnnotation and
      result = p
    )
  }
}

class ScriptEngineEval extends TaintTracking::Sink {
  ScriptEngineEval() {
    exists(MethodAccess evalCall |
      evalCall.getMethod().hasName("eval") and
      evalCall.getQualifier().getType() instanceof ScriptEngineType and
      evalCall.getArgument(0) = result
    )
  }
}

class StringLiteral extends TaintTracking::Sanitizer {
  StringLiteral() {
    exists(Literal l |
      l.getType().hasName("java.lang.String") and
      l.asExpr().isConstant() and
      result = l.asExpr()
    )
  }
}

class ScriptEngineInjectionFlowConfig extends TaintTracking::Configuration {
  ScriptEngineInjectionFlowConfig() { this = "ScriptEngineInjectionFlowConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof UntrustedInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof ScriptEngineEval }

  override predicate isSanitizer(DataFlow::Node sanitizer) { sanitizer instanceof StringLiteral }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Method m, Parameter p, Argument a |
      m.getAParameter() = p and
      a.getParameter() = p and
      pred.asParameter() = p and
      succ.asExpr() = a
    )
    or
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