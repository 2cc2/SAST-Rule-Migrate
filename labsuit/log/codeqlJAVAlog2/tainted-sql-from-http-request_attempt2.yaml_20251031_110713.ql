/**
 * @name Tainted SQL from HTTP request
 * @description Detected input from a HTTPServletRequest going into a SQL sink or statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use parameterized SQL queries or properly sanitize user input instead.
 * @kind problem
 * @problem.severity warning
 * @id java/tainted-sql-from-http-request
 * @tags security
 *       cwe: "89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
 *       owasp: "A01:2017 - Injection"
 *       owasp: "A03:2021 - Injection"
 */

import java
import DataFlow::PathGraph
import TaintTracking::Configuration
import DataFlow

class HttpRequestSource extends DataFlow::SourceNode {
  HttpRequestSource() {
    exists(Method m |
      m.hasQualifiedName("javax.servlet.http.HttpServletRequest", 
        ["getInputStream", "getParameter", "getParameterMap", "getParameterValues", "getReader", 
         "getCookies", "getHeader", "getHeaderNames", "getHeaders", "getPart", "getParts", "getQueryString"]) or
      m.hasQualifiedName("javax.servlet.ServletRequest", 
        ["getInputStream", "getParameter", "getParameterMap", "getParameterValues", "getReader", 
         "getCookies", "getHeader", "getHeaderNames", "getHeaders", "getPart", "getParts", "getQueryString"])
    |
      this.asExpr() = m.getACall()
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(Method m, MethodAccess ma |
      (m.hasQualifiedName("java.sql.Statement", 
          ["execute", "query", "executeUpdate", "batchUpdate"]) or
       m.getDeclaringType().hasQualifiedName("java.sql.PreparedStatement") or
       m.getDeclaringType().hasQualifiedName("java.sql.CallableStatement") or
       m.hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", 
          ["batchUpdate", "queryForObject", "queryForMap"])) and
      ma.getMethod() = m and
      this.asExpr() = ma.getArgument(0)
    )
    or
    exists(Expr e | 
      e.toString().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)") and
      this.asExpr() = e
    )
  }
}

class MyTaintConfig extends TaintTracking::Configuration {
  MyTaintConfig() { this = "MyTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof HttpRequestSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(Method m, MethodAccess ma |
      m.getDeclaringType().hasQualifiedName("java.sql.PreparedStatement") and
      ma.getMethod() = m and
      node.asExpr() = ma
    )
    or
    exists(Method m, MethodAccess ma |
      m.hasQualifiedName("org.apache.commons.lang.StringEscapeUtils", "escapeSql") and
      ma.getMethod() = m and
      node.asExpr() = ma
    )
  }
}

from MyTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), "Potential SQL injection vulnerability from HTTP request to SQL statement. User input should be properly sanitized.", 
  source.getNode(), "Source of user input"