/**
 * @name turbine-sqli
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.
 * @kind problem
 * @problem.severity warning
 * @id java/turbine-sqli
 * @tags security
 *       cwe:89
 *       owasp:a01:2017
 *       owasp:a03:2021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class SqlInjectionConfiguration extends TaintTracking::Configuration {
  SqlInjectionConfiguration() { this = "SqlInjectionConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      source.asExpr() = ma
    )
    or
    exists(BinaryExpr be |
      be.getOperator().toString() = "+" and
      source.asExpr() = be
    )
    or
    exists(Parameter p |
      p.getName() = "$SQL" and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("executeQuery") and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("", "BasePeer") or
        ma.getMethod().getDeclaringType().hasQualifiedName("", "GroupPeer")
      ) and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(StringLiteral sl | sanitizer.asExpr() = sl)
  }
}

from SqlInjectionConfiguration config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection. Use prepared statements instead."