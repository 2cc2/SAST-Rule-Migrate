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
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class HttpRequestSource extends RemoteFlowSource {
  HttpRequestSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("javax.servlet.http.HttpServletRequest", 
        ["getInputStream", "getParameter", "getParameterMap", "getParameterValues", "getReader", 
         "getCookies", "getHeader", "getHeaderNames", "getHeaders", "getPart", "getParts", "getQueryString"]) or
      ma.getMethod().hasQualifiedName("javax.servlet.ServletRequest", 
        ["getInputStream", "getParameter", "getParameterMap", "getParameterValues", "getReader", 
         "getCookies", "getHeader", "getHeaderNames", "getHeaders", "getPart", "getParts", "getQueryString"])
    |
      this = ma
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(MethodAccess ma |
      (ma.getMethod().hasQualifiedName("java.sql.Statement", 
          ["execute", "query", "executeUpdate", "batchUpdate"]) or
       ma.getMethod().getDeclaringType().hasQualifiedName("java.sql.PreparedStatement") or
       ma.getMethod().getDeclaringType().hasQualifiedName("java.sql.CallableStatement") or
       ma.getMethod().hasQualifiedName("org.springframework.jdbc.core.JdbcTemplate", 
          ["batchUpdate", "queryForObject", "queryForMap"])) and
      this.asExpr() = ma.getArgument(0)
    )
    or
    exists(Expr e | e.getParent() = _ and 
      e.toString().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)") and
      this.asExpr() = e
    )
  }
}

class Sanitizer extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql.PreparedStatement") and
      pred.asExpr() = ma and
      succ.asExpr() = ma.getArgument(_)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("org.apache.commons.lang.StringEscapeUtils", "escapeSql") and
      pred.asExpr() = ma and
      succ.asExpr() = ma.getArgument(0)
    )
  }
}

class TaintedSqlFromHttpRequestConfig extends TaintTracking::Configuration {
  TaintedSqlFromHttpRequestConfig() { this = "TaintedSqlFromHttpRequestConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof HttpRequestSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) { 
    sanitizer instanceof Sanitizer 
  }
}

from TaintedSqlFromHttpRequestConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), "Potential SQL injection vulnerability from HTTP request to SQL statement. User input should be properly sanitized.", 
  source.getNode(), "Source of user input"