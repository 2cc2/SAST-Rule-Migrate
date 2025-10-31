/**
 * @name Script Engine Injection
 * @description Detected potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()', otherwise, this is a code injection vulnerability.
 * @kind taint
 * @problem.severity Warning
 * @security-severity 8.0
 * @precision high
 * @id script-engine-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class ScriptEngineEvalMethod extends Method {
  ScriptEngineEvalMethod() {
    this.getDeclaringType().hasQualifiedName("javax.script", "ScriptEngine") and
    this.getName() = "eval"
  }
}

class UntrustedInput extends TaintTracking::Source {
  UntrustedInput() {
    exists(Method m, Parameter p |
      p = m.getAParameter() and
      not p.getAnAnnotation().getType().hasQualifiedName("javax.validation.constraints", "NotNull")
    )
  }
}

class ScriptEngineSink extends TaintTracking::Sink {
  ScriptEngineSink() {
    exists(MethodAccess ma |
      ma.getMethod() instanceof ScriptEngineEvalMethod and
      ma.getArgument(0) = this.asExpr()
    )
  }
}

class StringLiteralSanitizer extends TaintTracking::Sanitizer {
  StringLiteralSanitizer() {
    this.asExpr() instanceof StringLiteral
  }
}

class ScriptEngineInjectionConfig extends TaintTracking::Configuration {
  ScriptEngineInjectionConfig() {
    this = "Script Engine Injection Configuration"
  }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UntrustedInput
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ScriptEngineSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof StringLiteralSanitizer
  }
}

from ScriptEngineInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()'."