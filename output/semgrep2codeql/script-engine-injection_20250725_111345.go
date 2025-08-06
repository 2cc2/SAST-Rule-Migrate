/**
 * @name Script Engine Injection
 * @description Detected potential code injection using ScriptEngine. Ensure
 *              user-controlled data cannot enter '.eval()', otherwise, this is
 *              a code injection vulnerability.
 * @kind path-problem
 * @problem.severity warning
 * @id java/script-engine-injection
 * @tags security
 *       external/cwe/cwe-94
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class ScriptEngineClass extends RefType {
  ScriptEngineClass() { 
    this.hasQualifiedName("javax.script", "ScriptEngine")
  }
}

class ScriptEngineSource extends DataFlow::Node {
  ScriptEngineSource() {
    exists(Expr ma |
      ma.(Call).getCallee().getName().matches("getParameter%") and
      ma.(Call).getCallee().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asExpr() = ma
    )
  }
}

class ScriptEngineEvalCall extends DataFlow::Node {
  ScriptEngineEvalCall() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "eval" and
      ma.getMethod().getDeclaringType() instanceof ScriptEngineClass and
      this.asExpr() = ma
    )
  }
}

class ScriptEngineConfig extends TaintTracking::Configuration {
  ScriptEngineConfig() { this = "ScriptEngineConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof ScriptEngineSource }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      sink.asExpr() = ma.getAnArgument() and
      ma.getMethod().getName() = "eval" and
      ma.getMethod().getDeclaringType() instanceof ScriptEngineClass
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(StringLiteral sl | sanitizer.asExpr() = sl)
    or
    exists(Variable v, StringLiteral sl |
      sanitizer.asExpr() = v.getAnAccess() and
      v.getAnAssignedValue() = sl
    )
  }
}

from ScriptEngineConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential script engine injection from untrusted source"