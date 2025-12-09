/**
 * @name Script Engine Injection
 * @description Detected potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()'
 * @kind problem
 * @id java/script-engine-injection
 * @security-severity 8.0
 * @problem.severity warning
 * @precision high
 * @tags security
 *       external/cwe/cwe-094
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.scripting.ScriptEngine
import semmle.code.java.StringLiterals

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
      not p.getAnAnnotation().getType().getName() = "NotNull"
    )
  }
}

class ScriptEngineSink extends DataFlow::Node {
  ScriptEngineSink() {
    exists(MethodAccess ma |
      ma = this.asExpr() and
      ma.getMethod() instanceof ScriptEngineEvalMethod and
      this.getNode() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    this.getNode() instanceof StringLiteral
  }
}

class ScriptEngineInjectionConfig extends TaintTracking::Configuration {
  ScriptEngineInjectionConfig() { this = "ScriptEngineInjectionConfig" }

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
    exists(FieldRead fr, FieldWrite fw |
      fr.getField() = fw.getField() and
      pred.asExpr() = fw.getRhs() and
      succ.asExpr() = fr.getExpr()
    )
    or
    exists(Parameter param, MethodAccess call |
      pred.asParameter() = param and
      succ.asExpr() = call.getArgument(param.getPosition())
    )
  }
}

from ScriptEngineInjectionConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()'",
  source, "Untrusted input"