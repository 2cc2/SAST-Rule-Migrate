/**
 * @name Tainted SQL from HTTP Request
 * @description Detected input from a HTTPServletRequest going into a SQL sink or statement.
 *              This could lead to SQL injection if variables are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @id java/tainted-sql-from-http-request
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class ServletSource extends DataFlow::Node {
  ServletSource() {
    exists(MethodAccess ma |
      (ma.getCallee().getName().matches("getInputStream") or
       ma.getCallee().getName().matches("getParameter%") or
       ma.getCallee().getName().matches("getQueryString") or
       ma.getCallee().getName().matches("getHeader%") or
       ma.getCallee().getName().matches("getCookies") or
       ma.getCallee().getName().matches("getPart%")) and
      (ma.getCallee().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") or
       ma.getCallee().getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest")) and
      this.asExpr() = ma
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(MethodAccess ma |
      (ma.getCallee().getDeclaringType().hasQualifiedName("java.sql", "Statement") or
       ma.getCallee().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") or
       ma.getCallee().getDeclaringType().hasQualifiedName("java.sql", "CallableStatement") or
       ma.getCallee().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate")) and
      (ma.getCallee().getName().matches("execute%") or
       ma.getCallee().getName() = "query" or
       ma.getCallee().getName() = "batchUpdate") and
      this.asExpr() = ma.getAnArgument()    
    )
    or
    exists(StringLiteral sql |
      sql.getValue().matches("(?i)(SELECT.*|INSERT.*|UPDATE.*)") and
      exists(MethodAccess ma | 
        ma.getAnArgument() = sql and
        ma.getCallee().getName().matches("execute%|query|batchUpdate") and
        this.asExpr() = sql
      )
    )
  }
}

class SqlTaintConfig extends TaintTracking::Configuration {
  SqlTaintConfig() { this = "SqlTaintConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof ServletSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) { none() }
}

from SqlTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential SQL injection from untrusted HTTP request"