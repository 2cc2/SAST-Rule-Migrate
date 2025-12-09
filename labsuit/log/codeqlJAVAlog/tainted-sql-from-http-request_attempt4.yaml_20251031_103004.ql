/**
 * @name Tainted SQL from HTTP request
 * @description Detected input from a HTTPServletRequest going into a SQL sink or statement.
 * @id tainted-sql-from-http-request
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.8
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.SqlInjection

class HttpRequestSource extends TaintTracking::Source {
  HttpRequestSource() {
    exists(MethodAccess ma |
      (
        ma.getMethod().hasName("getParameter", "getParameterMap", "getParameterValues", "getQueryString") and
        ma.getReceiverType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
      ) or
      (
        ma.getMethod().hasName("getInputStream", "getReader", "getCookies", "getHeader", "getHeaderNames", 
                              "getHeaders", "getPart", "getParts") and
        (ma.getReceiverType().hasQualifiedName("javax.servlet", "ServletRequest") or
         ma.getReceiverType().hasQualifiedName("javax.servlet.http", "HttpServletRequest"))
      )
    ) and
    this = ma.asExpr()
  }
}

class SqlExecutionSink extends TaintTracking::Sink {
  SqlExecutionSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().hasName("execute", "executeQuery", "executeUpdate", "batchUpdate") and
        ma.getReceiverType().hasQualifiedName("java.sql", "Statement")
      ) or
      ma.getReceiverType().hasQualifiedName("java.sql", "PreparedStatement") or
      ma.getReceiverType().hasQualifiedName("java.sql", "CallableStatement") or
      (
        ma.getMethod().hasName("batchUpdate", "queryForObject", "queryForMap") and
        ma.getReceiverType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate")
      ) or
      ma.getArgument(0).toString().matches("%SELECT%|%INSERT%|%UPDATE%")
    ) and
    this = ma.asExpr()
  }
}

class SafeSqlSanitizer extends TaintTracking::Sanitizer {
  SafeSqlSanitizer() {
    exists(MethodAccess ma |
      ma.getReceiverType().hasQualifiedName("java.sql", "PreparedStatement") or
      (
        ma.getMethod().hasName("escapeSql") and
        ma.getReceiverType().hasQualifiedName("org.apache.commons.lang", "StringEscapeUtils")
      )
    ) and
    this = ma.asExpr()
  }
}

class TaintedSqlFromHttpRequest extends TaintTracking::Configuration {
  TaintedSqlFromHttpRequest() { this = "Tainted SQL from HTTP request" }

  override predicate isSource(TaintTracking::Source source) { source instanceof HttpRequestSource }

  override predicate isSink(TaintTracking::Sink sink) { sink instanceof SqlExecutionSink }

  override predicate isSanitizer(TaintTracking::Sanitizer sanitizer) {
    sanitizer instanceof SafeSqlSanitizer
  }
}

from TaintedSqlFromHttpRequest config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected input from a HTTPServletRequest going into a SQL sink ($@). This could lead to SQL injection.", 
  source.getNode(), "user input source",
  sink.getNode(), "SQL execution sink"