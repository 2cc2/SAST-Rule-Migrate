/**
 * @name Tainted SQL from HTTP Request
 * @description Detected input from a HTTPServletRequest going into a SQL sink or statement.
 *              This could lead to SQL injection if variables in the SQL statement are not
 *              properly sanitized. Use parameterized SQL queries or properly sanitize user input instead.
 * @kind path-problem
 * @problem.severity warning
 * @id java/tainted-sql-from-http-request
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjectionQuery
import semmle.code.java.dataflow.TaintTracking

class HttpRequestSource extends RemoteFlowSource {
  HttpRequestSource() {
    exists(Method m | 
      m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      m.getName().matches("getInputStream|getParameter|getParameterMap|getParameterValues|getReader|getCookies|getHeader|getHeaderNames|getHeaders|getPart|getParts|getQueryString") and
      this.asExpr() = m.getACall()
    )
    or
    exists(Method m | 
      m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest") and
      m.getName().matches("getInputStream|getParameter|getParameterMap|getParameterValues|getReader|getCookies|getHeader|getHeaderNames|getHeaders|getPart|getParts|getQueryString") and
      this.asExpr() = m.getACall()
    )
  }
}

class SqlExecutionSink extends SqlInjectionSink {
  SqlExecutionSink() {
    exists(Method m |
      (
        m.getDeclaringType().hasQualifiedName("java.sql", "Statement") and
        m.getName().matches("execute|query|executeUpdate|batchUpdate")
      )
      or
      m.getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement")
      or
      m.getDeclaringType().hasQualifiedName("java.sql", "CallableStatement")
      or
      (
        m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
        m.getName().matches("batchUpdate|queryForObject|queryForMap")
      )
    ) and
    this.asExpr() = m.getACall()
    or
    exists(MethodAccess expr |
      (
        expr.getArgument(0).toString().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)")
      ) and
      this.asExpr() = expr
    )
  }
}

class SqlSanitizer extends TaintTracking::Sanitizer {
  SqlSanitizer() {
    exists(Method m |
      m.getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") and
      this.asExpr() = m.getACall()
    )
    or
    exists(Method m |
      m.getDeclaringType().hasQualifiedName("org.apache.commons.lang", "StringEscapeUtils") and
      m.getName() = "escapeSql" and
      this.asExpr() = m.getACall()
    )
  }
}

class TaintedSQLFlowConfig extends TaintTracking::Configuration {
  TaintedSQLFlowConfig() { this = "TaintedSQLFlowConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof HttpRequestSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlExecutionSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) { sanitizer instanceof SqlSanitizer }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedSQLFlowConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SQL injection vulnerability from $@ to $@.",
  source.getNode(), "user input",
  sink.getNode(), "SQL execution"