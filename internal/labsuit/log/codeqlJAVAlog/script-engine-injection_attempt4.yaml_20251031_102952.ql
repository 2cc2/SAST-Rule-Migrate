/**
 * @id script-engine-injection
 * @severity Warning
 * @kind path-problem
 * @name Script Engine Injection
 * @description Detected potential code injection using ScriptEngine. Ensure user-controlled data cannot '.eval()'.
 * @kind taint
 * @problem.severity warning
 * @security-severity 7.5
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/owasp/a03
 */
import java
import DataFlow
import TaintTracking
import semmle.code.java.dataflow.FlowSources

class ScriptEngineEvalMethod extends Callable {
  ScriptEngineEvalMethod() {
    this.getDeclaringType().hasQualifiedName("javax.script", "ScriptEngine") and
    this.hasName("eval")
  }
}

class UntrustedInputSource extends DataFlow::Node {
  UntrustedInputSource() {
    exists(Parameter p |
      p = this.asParameterNode() and
      not p.getAnAnnotation().hasQualifiedName("javax.validation.constraints", "NotNull")
    )
  }
}

class ScriptEngineSink extends DataFlow::Node {
  ScriptEngineSink() {
    exists(MethodCall call |
      call.getMethod() instanceof ScriptEngineEvalMethod and
      this.asExpr() = call.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    this.asExpr() instanceof StringLiteralExpr and
    this.asExpr().toString().matches("\".*\"")
  }
}

class ScriptEngineInjectionConfig extends TaintTracking::Configuration {
  ScriptEngineInjectionConfig() { this = "ScriptEngineInjection" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UntrustedInputSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ScriptEngineSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof StringLiteralSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Parameter p, MethodCall call |
      pred.asParameterNode() = p and
      succ.asExpr() = call.getAnArgument() and
      call.getMethod() = p.getCallable()
    )
    or
    exists(FieldAccess read, FieldAccess write |
      pred.asExpr() = read and
      succ.asExpr() = write and
      read.getField() = write.getField()
    )
  }
}

from ScriptEngineInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential script engine injection from $@", source, source.toString()