/**
 * @name Tainted command from HTTP request
 * @description Detected input from a HTTPServletRequest going into a 'ProcessBuilder' or 'exec' command. This could
 *    lead to command injection if variables passed into the exec commands are not properly sanitized. Instead,
 *    avoid using these OS commands with user-supplied input, or, if you must use these commands, use a
 *    whitelist of specific values.
 * @kind path-problem
 * @problem.severity error
 * @id java/tainted-cmd-from-http-request
 * @tags security
 *       external/cwe/cwe-078
 *       owasp-a01
 *       owasp-a03
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Servlets
import DataFlow::PathGraph

class HttpRequestSource extends DataFlow::Node {
  HttpRequestSource() {
    exists(MethodAccess ma | 
      ma.getMethod().getName() = "getCookies" and
      this.asExpr() = ma.getQualifier()
    ) or
    exists(MethodAccess ma | 
      ma.getMethod().getName() = "getValue" and
      exists(DataFlow::Node cookieVar | 
        ma.getQualifier() = cookieVar.asExpr() and
        cookieVar.getType() instanceof TypeCookie and
        this.asExpr() = ma
      )
    )
  }
}

class CommandSink extends DataFlow::Node {
  CommandSink() {
    exists(ConstructorCall cc | 
      cc.getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder") and
      this.asExpr() = cc
    ) or
    exists(MethodAccess ma | 
      ma.getMethod().hasName("exec") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      this.asExpr() = ma.getArgument(0)
    ) or
    exists(MethodAccess ma | 
      ma.getMethod().hasName("command") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class TaintedCommandFromHttpRequest extends TaintTracking::Configuration {
  TaintedCommandFromHttpRequest() { this = "TaintedCommandFromHttpRequest" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof HttpRequestSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandSink
  }
}

from TaintedCommandFromHttpRequest config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "Input from HTTP request flows into OS command and may cause command injection"