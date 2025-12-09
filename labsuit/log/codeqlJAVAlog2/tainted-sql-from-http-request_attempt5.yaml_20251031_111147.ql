/**
 * @name Tainted SQL from HTTP request
 * @description Detected input from a HTTPServletRequest going into a SQL sink or statement.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision high
 * @id java/tainted-sql-from-http-request
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */

import codeql.java.dataflow.internal.FlowSources
import codeql.java.dataflow.internal.DataFlow
import codeql.java.dataflow.internal.TaintTracking
import codeql.java.Method

class HttpRequestSource extends DataFlow::Node {
  HttpRequestSource() {
    this.asExpr() instanceof MethodAccess and
    exists(MethodAccess ma |
      ma = this.asExpr() and
      (
        (ma.getMethod().getName().matches("getInputStream|getParameter|getParameterMap|getParameterValues|getReader|getCookies|getHeader|getHeaderNames|getHeaders|getPart|getParts|getQueryString") and
         ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet.http", "HttpServletRequest")) or
        (ma.getMethod().getName().matches("getInputStream|getParameter|getParameterMap|getParameterValues|getReader|getCookies|getHeader|getHeaderNames|getHeaders|getPart|getParts|getQueryString") and
         ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet", "ServletRequest"))
      )
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    this.asExpr() instanceof MethodAccess and
    exists(MethodAccess ma |
      ma = this.asExpr() and
      (
        (ma.getMethod().getName().matches("execute|executeUpdate|batchUpdate|query|queryForObject|queryForMap") and
         (ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") or
          ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
          ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "CallableStatement") or
          ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate")))
        or
        (exists(DataFlow::StringNode str |
          str.getValue().regexpMatch("(?i)(^SELECT.*|^INSERT.*|^UPDATE.*)") and
          ma.getArgument(0) = str
        ))
      )
    )
  }
}

class TaintTrackingConfig extends TaintTracking::Configuration {
  TaintTrackingConfig() { this = "TaintTrackingConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof HttpRequestSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma = node.asExpr() and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
        (ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.lang", "StringEscapeUtils") and
         ma.getMethod().getName() = "escapeSql")
      )
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintTrackingConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Detected input from a HTTPServletRequest going into a SQL sink or statement."