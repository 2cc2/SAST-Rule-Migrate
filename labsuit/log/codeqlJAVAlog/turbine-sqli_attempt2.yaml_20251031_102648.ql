/**
 * @name Turbine SQL injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection 
 *              if variables in the SQL statement are not properly sanitized.
 * @kind problem
 * @id turbine-sqli
 * @severity Warning
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking2
import semmle.code.java.MethodAccess
import semmle.code.java.Parameter
import semmle.code.java.Literal

class SqlConcatSource extends DataFlow::Node {
  SqlConcatSource() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "format" and ma.getMethod().getDeclaringType().getName() = "String") or
      ma.getArgument(0).toString().matches("%+%")
    ) and
    this.asExpr() = ma
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
    exists(MethodAccess ma |
      (ma.getMethod().getDeclaringType().getName() = "BasePeer" or
       ma.getMethod().getDeclaringType().getName() = "GroupPeer") and
      ma.getMethod().getName() = "executeQuery" and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class LiteralSanitizer extends DataFlow::Node {
  LiteralSanitizer() {
    exists(Literal l |
      l.toString().matches("\".*\"") and
      this.asExpr() = l
    )
  }
}

class TurbineSQLInjectionConfiguration extends TaintTracking2::Configuration {
  TurbineSQLInjectionConfiguration() { this = "TurbineSQLInjectionConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlConcatSource or
    source instanceof SqlParamSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof LiteralSanitizer
  }
}

from TurbineSQLInjectionConfiguration cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead."