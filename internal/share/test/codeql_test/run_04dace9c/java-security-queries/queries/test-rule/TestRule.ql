/**
 * @name Tainted environment from HTTP request
 * @description Detected input from a HTTPServletRequest going into the environment variables of an 'exec' command.
 *              Instead, call the command with user-supplied arguments by using the overloaded method with one String array as the argument.
 *              `exec({"command", "arg1", "arg2"})`.
 * @kind path-problem
 * @problem.severity error
 * @id java/tainted-env-from-http-request
 * @tags security
 *       external/cwe/cwe-454
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Servlets

class HttpRequestSource extends DataFlow::Node {
  HttpRequestSource() {
    exists(Call ma |
      (ma.getCallee().getName() = "getCookies" and 
       ma.getCallee().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
       this.asExpr() = ma.getQualifier()) or
      (exists(Method m | 
        m = ma.getCallee() and
        m.hasName("getValue") and
        m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
        this.asExpr() = ma.getQualifier()
      ))
    )
  }
}

class RuntimeExecEnvSink extends DataFlow::Node {
  RuntimeExecEnvSink() {
    exists(Call ma |
      ma.getCallee().getName() = "exec" and
      ma.getCallee().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
      ma.getArgument(1) = this.asExpr()
    )
  }
}

predicate isSource(DataFlow::Node source) { source instanceof HttpRequestSource }

predicate isSink(DataFlow::Node sink) { sink instanceof RuntimeExecEnvSink }

from DataFlow::Node source, DataFlow::Node sink
where TaintTracking::localTaint(source, sink) and
  isSource(source) and
  isSink(sink)
select sink, "Potential unsafe execution with tainted environment variables from HTTP request"