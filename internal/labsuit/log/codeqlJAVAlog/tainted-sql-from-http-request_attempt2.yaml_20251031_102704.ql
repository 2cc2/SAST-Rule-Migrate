/**
 * @name Tainted SQL from HTTP request
 * @description Detected input from a HTTPServletRequest going into a SQL sink or statement.
 *              This could lead to SQL injection if variables in the SQL statement are not
 *              properly sanitized. Use parameterized SQL queries or properly sanitize user input instead.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision high
 * @id java/tainted-sql-from-http-request
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjection
import semmle.code.java.dataflow.TaintTracking

class HttpRequestSource extends TaintTracking::Source {
  HttpRequestSource() {
    exists(MethodAccess ma |
      (
        ma.getMethod().hasName(["getInputStream", "getParameter", "getParameterMap", "getParameterValues",
                               "getReader", "getCookies", "getHeader", "getHeaderNames", "getHeaders",
                               "getPart", "getParts", "getQueryString"]) and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
      ) or
      (
        ma.getMethod().hasName(["getInputStream", "getParameter", "getParameterMap", "getParameterValues",
                               "getReader", "getCookies", "getHeader", "getHeaderNames", "getHeaders",
                               "getPart", "getParts", "getQueryString"]) and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest")
      )
    ) and
    this.asParameter() = result
  }
}

class SqlExecutionSink extends TaintTracking::Sink {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().hasName(["execute", "query", "executeUpdate", "batchUpdate"]) and
        ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement")
      ) or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "CallableStatement") or
      (
        ma.getMethod().hasName(["batchUpdate", "queryForObject", "queryForMap"]) and
        ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate")
      ) or
      ma.getArgument(0).toString().matches("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)")
    ) and
    this.asParameter() = ma
  }
}

class SqlParameterSanitizer extends TaintTracking::Sanitizer {
  SqlParameterSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") and
      this.asParameter() = ma
    )
  }
}

class SqlEscapeSanitizer extends TaintTracking::Sanitizer {
  SqlEscapeSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("escapeSql") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.lang", "StringEscapeUtils") and
      this.asParameter() = ma
    )
  }
}

from HttpRequestSource source, SqlExecutionSink sink
where TaintTracking::hasFlowPath(source, sink)
select sink, "Potential SQL injection from HTTP request parameter to SQL execution"