/**
 * @name Command injection through formatted runtime call
 * @description Detects when user-controlled input is passed to Runtime.exec() or loadLibrary()
 *              without proper sanitization, which could lead to command injection.
 * @kind problem
 * @problem.severity error
 * @id java/command-injection-formatted-runtime-call
 * @tags security
 *       external/cwe/cwe-078
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java.dataflow.DataFlow
import java.dataflow.TaintTracking

class CommandInjectionSrc extends DataFlow::Node {
  CommandInjectionSrc() {
    exists(DataFlow::ParameterNode p | this = p and not p.getDefaultValue().isLiteral()) or
    exists(DataFlow::LocalScopeVariableNode l | this = l and not l.getInitializer().isLiteral())
  }
}

class RuntimeSink extends DataFlow::Node {
  RuntimeSink() {
    exists(DataFlow::MethodAccessNode ma, DataFlow::Method m |
      m.hasName(["exec", "loadLibrary"]) and
      m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      ma.getMethod() = m and
      (
        this.asNode() = ma.getArgument(0) or
        this.asNode() = ma.getArgument(1) or
        this.asNode() = ma.getArgument(2) or
        this.asNode() = ma.getQualifier()
      )
    )
  }
}

class LiteralSanitizer extends DataFlow::Node {
  LiteralSanitizer() {
    this.asNode().getType() instanceof PrimitiveType or
    exists(DataFlow::LiteralNode lit | this.asNode() = lit)
  }
}

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof CommandInjectionSrc
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof RuntimeSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof LiteralSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DataFlow::MethodAccessNode ma |
      ma.getMethod().hasName("format") and
      succ.asNode() = ma and
      TaintTracking::localTaintStep(pred, succ)
    )
    or
    exists(BinaryExpr bo |
      bo.getOperator() = "+" and
      succ.asNode() = bo and
      TaintTracking::localTaintStep(pred, succ)
    )
  }
}

from CommandInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Formatted string used in Runtime call may lead to command injection. $" + source.toString() + "$ is user-controlled input.",
  source, "Potential user input flows here"