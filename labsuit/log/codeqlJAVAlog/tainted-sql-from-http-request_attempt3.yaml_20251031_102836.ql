/**
 * @name Tainted SQL from HTTP Request
 * @description Detected input from a HTTPServletRequest going into a SQL sink or statement.
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id java/tainted-sql-from-http-request
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import DataFlow::PathGraph
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjection
import semmle.code.java.security.QueryInjection

class HttpRequestSource extends DataFlow::Node {
  HttpRequestSource() {
    exists(MethodAccess ma |
      (ma.getMethod().hasName(["getInputStream", "getParameter", "getParameterMap", "getParameterValues", 
                              "getReader", "getCookies", "getHeader", "getHeaderNames", "getHeaders", 
                              "getPart", "getParts", "getQueryString"]) and
       ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")) or
      (ma.getMethod().hasName(["getInputStream", "getParameter", "getParameterMap", "getParameterValues",
                              "getReader", "getQueryString"]) and
       ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest"))
    ) and
    this.asExpr() = ma
  }
}

class SqlExecutionSink extends DataFlow::Node {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      (ma.getMethod().hasName(["execute", "executeQuery", "executeUpdate", "batchUpdate"]) and
       ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement")) or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "CallableStatement") or
      (ma.getMethod().hasName(["batchUpdate", "queryForObject", "queryForMap"]) and
       ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate")) or
      exists(ma.getArgument(0) |
        ma.getArgument(0).toString().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)")
      )
    ) and
    this.asExpr() = ma
  }
}

class SqlParameterSanitizer extends DataFlow::BarrierGuard {
  SqlParameterSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") and
      this.asExpr() = ma
    )
  }
}

class SqlEscapeSanitizer extends DataFlow::BarrierGuard {
  SqlEscapeSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "escapeSql" and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.lang", "StringEscapeUtils") and
      this.asExpr() = ma
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, SqlParameterSanitizer sanitizer1, SqlEscapeSanitizer sanitizer2
where DataFlow::flowPath(source, sink)
  and source.getNode() instanceof HttpRequestSource
  and sink.getNode() instanceof SqlExecutionSink
  and not DataFlow::hasBarrier(source, sink, sanitizer1)
  and not DataFlow::hasBarrier(source, sink, sanitizer2)
select sink.getNode(), source.getNode(),
  "Detected input from a HTTPServletRequest going into a SQL sink or statement. " +
  "This could lead to SQL injection if variables in the SQL statement are not properly sanitized. " +
  "Use parameterized SQL queries or properly sanitize user input instead."