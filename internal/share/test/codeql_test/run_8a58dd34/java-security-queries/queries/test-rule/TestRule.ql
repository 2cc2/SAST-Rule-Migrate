/**
 * @name Insecure SMTP Connection
 * @description Detects insecure SMTP connections that trust any SSL certificate without proper host verification.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id java/insecure-smtp-connection
 * @tags security
 *       external/cwe/cwe-297
 *       external/owasp/a07
 */

import java
import semmle.code.java.dataflow.FlowSources

class SimpleEmailCreation extends MethodAccess {
  SimpleEmailCreation() {
    getMethod().getName() = "SimpleEmail" and
    getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.mail", "SimpleEmail")
  }
}

class InsecureSmtpConfig extends DataFlow::Node {
  InsecureSmtpConfig() {
    exists(SimpleEmailCreation creation |
      creation.getQualifier() = this.asExpr() and
      not exists(MethodAccess setConfig |
        setConfig.getMethod().getName() = "setSSLCheckServerIdentity" and
        setConfig.getArgument(0).(Literal).getValue() = "true" and
        setConfig.getQualifier() = this.asExpr()
      )
    )
  }
}

class InsecureSmtpFlow extends DataFlow::Configuration {
  InsecureSmtpFlow() { this = "InsecureSmtpFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof InsecureSmtpConfig
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess send |
      send.getMethod().getName() = "send" and
      send.getQualifier() = sink.asExpr()
    )
  }
}

from InsecureSmtpFlow flow, DataFlow::Node source, DataFlow::Node sink
where flow.hasFlow(source, sink)
select sink, "Insecure SMTP connection detected. This connection will trust any SSL certificate. " +
  "Enable certificate verification by setting 'email.setSSLCheckServerIdentity(true)'."