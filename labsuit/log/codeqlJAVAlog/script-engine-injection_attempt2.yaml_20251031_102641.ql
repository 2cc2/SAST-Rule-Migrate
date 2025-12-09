/**
 * @name Script Engine Injection
 * @description Detected potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()'
 * @kind problem
 * @id java/script-engine-injection
 * @security-severity 8.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.scripting.ScriptEngine

class ScriptEngineEvalMethod extends Method {
  ScriptEngineEvalMethod() {
    this.getDeclaringType().getQualifiedName() = "javax.script.ScriptEngine" and
    this.getName() = "eval"
  }
}

class UntrustedInputSource extends DataFlow::Node {
  UntrustedInputSource() {
    exists(MethodParam p |
      p = this.asParameter() and
      not p.getAnAnnotation().getType().hasQualifiedName("javax.validation.constraints", "NotNull")
    )
  }
}

class ScriptEngineSink extends DataFlow::Node {
  ScriptEngineSink() {
    exists(MethodAccess ma |
      ma.getMethod() instanceof ScriptEngineEvalMethod and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(StringLiteral sl | this.asExpr() = sl)
  }
}

class ScriptEngineTaintTrackingConfiguration extends TaintTracking::Configuration {
  ScriptEngineTaintTrackingConfiguration() {
    this = "ScriptEngineTaintTrackingConfiguration"
  }

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
    TaintTracking::localTaintStep(node1, node2) or
    exists(FieldRead fr, FieldWrite fw |
      fr.getField() = fw.getField() and
      node1.asExpr() = fr.getRhs() and
      node2.asExpr() = fw.getLhs()
    ) or
    exists(Parameter p, MethodAccess ma |
      node1.asParameter() = p and
      node2.asExpr() = ma.getArgument(p.getPosition())
    )
  }
}

from ScriptEngineTaintTrackingConfiguration cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()'",
  source, "User input"