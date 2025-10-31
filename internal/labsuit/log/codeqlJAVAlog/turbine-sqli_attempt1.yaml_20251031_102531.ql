/**
 * @name turbine-sqli
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id java/turbine-sqli
 * @tags security
 *       cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
 *       owasp: "A01:2017 - Injection"
 *       owasp: "A03:2021 - Injection"
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class SqlConcatSource extends DataFlow::Node {
  SqlConcatSource() {
    exists(Method m | 
      (m.hasName("format") and m.getDeclaringType().hasQualifiedName("java.lang", "String")) |
      this.asExpr() = m.getACall() and this.getNode().getCode().matches("%+%")
    )
  }
}

class SqlParamSource extends DataFlow::Node {
  SqlParamSource() {
    exists(Parameter p | 
      p.getName() = "$SQL" and
      this.asParameter() = p
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(Method m, MethodAccess ma |
      (m.getName() = "executeQuery" and 
       (m.getDeclaringType().hasQualifiedName("", "BasePeer") or
        m.getDeclaringType().hasQualifiedName("", "GroupPeer"))) and
      ma.getMethod() = m and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class LiteralSanitizer extends DataFlow::Node {
  LiteralSanitizer() {
    exists(Literal l | 
      l.getCode().matches("^\".+\"$") and
      this.asExpr() = l
    )
  }
}

class TurbineSqlConfiguration extends TaintTracking::Configuration {
  TurbineSqlConfiguration() { this = "TurbineSqlConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlConcatSource or
    source instanceof SqlParamSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof LiteralSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma, Parameter p |
      ma.getAnArgument() = pred.asExpr() and
      p = succ.asParameter() and
      p = ma.getTarget().getAParameter()
    )
  }
}

from TurbineSqlConfiguration config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Potential SQL injection vulnerability due to unsanitized SQL construction"