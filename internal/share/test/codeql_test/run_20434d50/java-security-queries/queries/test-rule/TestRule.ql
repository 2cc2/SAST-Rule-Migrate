/**
 * @name CRLF Injection in Logs
 * @description When data from an untrusted source is put into a logger and not neutralized correctly,
 *              an attacker could forge log entries or include malicious content.
 * @kind path-problem
 * @problem.severity warning
 * @id java/crlf-injection-logs
 * @tags security
 *       external/cwe/cwe-93
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class Logger extends RefType {
  Logger() { 
    this.hasQualifiedName("org.slf4j", "Logger") or
    this.hasQualifiedName("org.apache.logging.log4j", "Logger")
  }
}

predicate isLoggerMethod(Method m) {
  m.getDeclaringType() instanceof Logger
}

class LoggerParameter extends DataFlow::Node {
  LoggerParameter() {
    exists(Expr ma |
      ma.(Call).getCallee().getName().matches("getParameter%") and
      ma.(Call).getCallee().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      this.asExpr() = ma
    )
  }
}

class LoggerSink extends DataFlow::Node {
  LoggerSink() {
    exists(Expr ma |
      (isLoggerMethod(ma.(Call).getCallee()) or ma.(Call).getCallee().getName().matches("log")) and
      this.asExpr() = ma.(Call).getArgument(0)
    )
  }
}

class LoggerConfig extends TaintTracking::Configuration {
  LoggerConfig() { this = "LoggerConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof LoggerParameter }

  override predicate isSink(DataFlow::Node sink) { sink instanceof LoggerSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) { none() }
}

from LoggerConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential CRLF injection in logs from untrusted source"