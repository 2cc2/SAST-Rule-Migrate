/**
 * @name Command Injection via Runtime.exec() or loadLibrary()
 * @id command-injection-formatted-runtime-call
 * @description A formatted or concatenated string was detected as input to a java.lang.Runtime
 *              call. This is dangerous if a variable is controlled by user input and could result in
 *              a command injection. Ensure your variables are not controlled by users or sufficiently
 *              sanitized.
 * @kind taint
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-078
 *       owasp-a01:2017
 *       owasp-a03:2021
 */

import java
import DataFlow::PathGraph
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import semmle.code.java.Concat

class CommandInjectionSrc extends DataFlow::Node {
  CommandInjectionSrc() {
    exists(Method m, Parameter p | 
      m = p.getMethod() and
      this.asParameter() = p
    ) or
    exists(Variable l | 
      this.asVariable() = l
    )
  }
  
  override predicate isSource(DataFlow::Node source) {
    not exists(Literal l | source.asExpr() = l)
  }
}

class RuntimeSink extends DataFlow::Node {
  RuntimeSink() {
    exists(MethodAccess ma, Method m | 
      ma.getMethod() = m and
      m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      (
        (m.hasName("exec") and (ma.getArgument(0) = this.asExpr() or
                               ma.getArgument(1) = this.asExpr() or
                               ma.getArgument(2) = this.asExpr())) or
        (m.hasName("loadLibrary") and ma.getArgument(0) = this.asExpr())
      )
    )
  }
}

class LiteralSanitizer extends DataFlow::Node {
  LiteralSanitizer() {
    exists(Literal l | this.asExpr() = l)
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
  
  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof LiteralSanitizer
  }
  
  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma | 
      (ma.getMethod().hasName("concat") or ma.getMethod().getName() = "+") and
      node1.asExpr() = ma.getAnArgument() and
      node2.asExpr() = ma.getArgument(0)
    ) or
    exists(MethodAccess ma | 
      (ma.getMethod().hasName("format") or ma.getMethod().hasName("printf")) and
      node1.asExpr() = ma.getAnArgument() and
      node2.asExpr() = ma.getArgument(0)
    )
  }
}

from CommandInjectionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, 
  "Potential command injection: user-controlled input may reach $@.", source, source.toString()