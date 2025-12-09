/**
 * @name Tainted SQL from HTTP request
 * @description Detected input from a HTTPServletRequest going into a SQL sink or statement.
 * @kind problem
 * @id java/tainted-sql-from-http-request
 * @security-severity 8.8
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.SqlInjection
import semmle.code.java.frameworks.Servlets

class HttpRequestSource extends TaintTracking::Source {
  HttpRequestSource() {
    exists(MethodAccess ma |
      (ma.getMethod().hasName(["getParameter", "getParameterMap", "getParameterValues", "getReader", 
                              "getInputStream", "getCookies", "getHeader", "getHeaderNames", 
                              "getHeaders", "getPart", "getParts", "getQueryString"]) and
       ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet.http", "HttpServletRequest")) or
      (ma.getMethod().hasName(["getParameter", "getParameterMap", "getParameterValues", "getReader",
                              "getInputStream", "getCookies", "getHeader", "getHeaderNames",
                              "getHeaders", "getPart", "getParts", "getQueryString"]) and
       ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest"))
    )
    and this.asExpr() = ma
  }
}

class SqlSink extends TaintTracking::Sink {
  SqlSink() {
    exists(MethodAccess ma |
      (ma.getMethod().hasName(["execute", "executeQuery", "executeUpdate", "batchUpdate"]) and
       ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement")) or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "CallableStatement") or
      (ma.getMethod().hasName(["batchUpdate", "queryForObject", "queryForMap"]) and
       ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate")) or
      ma.getArgument(0).toString().regexpMatch("(?i)(SELECT|INSERT|UPDATE).*")
    )
    and this.asExpr() = ma
  }
}

class PreparedStatementSanitizer extends TaintTracking::Sanitizer {
  PreparedStatementSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement")
      and this.asExpr() = ma
    )
  }
}

class StringEscapeSanitizer extends TaintTracking::Sanitizer {
  StringEscapeSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("escapeSql") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.lang", "StringEscapeUtils")
      and this.asExpr() = ma
    )
  }
}

class TaintedSqlFromHttpRequestConfig extends TaintTracking::Configuration {
  TaintedSqlFromHttpRequestConfig() { this = "TaintedSqlFromHttpRequestConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof HttpRequestSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof PreparedStatementSanitizer or
    sanitizer instanceof StringEscapeSanitizer
  }
}

from TaintedSqlFromHttpRequestConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Detected input from a HTTPServletRequest going into a SQL sink or statement. " +
  "This could lead to SQL injection if variables in the SQL statement are not " +
  "properly sanitized. Use parameterized SQL queries or properly sanitize user input instead."