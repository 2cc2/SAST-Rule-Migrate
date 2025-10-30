/**
 * @name Tainted system command
 * @kind problem
 * @problem.severity error
 * @id java/tainted-system-command
 * @tags security
 *       external/cwe/cwe-078
 *       external/owasp/a01
 *       external/owasp/a03
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.spring.SpringController

class CommandExecutionSink extends DataFlow::Node {
  CommandExecutionSink() {
    exists(MethodAccess ma |
      (ma.getMethod().hasName("exec") and ma.getMethod().getDeclaringType() instanceof TypeRuntime) or
      ((ma.getMethod().hasName("command") or ma.getMethod().hasName("start")) and 
       ma.getMethod().getDeclaringType() instanceof TypeProcessBuilder)
    |
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class TaintedSource extends DataFlow::Node {
  TaintedSource() {
    exists(Method m, Parameter p | 
      p = m.getAParameter() and
      not p.getType() instanceof PrimitiveType and
      (
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestHeader") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "CookieValue") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "ModelAttribute")
      )
    | this.asParameter() = p)
  }
}

class TaintTrackingConfiguration extends TaintTracking::Configuration {
  TaintTrackingConfiguration() { this = "TaintTrackingConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof TaintedSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandExecutionSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "append" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      node1.asExpr() = ma.getArgument(0) and
      node2.asExpr() = ma
    )
  }
}

from TaintTrackingConfiguration cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, 
  "Detected user input entering a method which executes a system command. This could result in a command injection vulnerability.",
  source, "User input from here", 
  sink, "Shell command executed here"