/**
 * @name Tainted SQL String
 * @description Detected user input used to manually construct a SQL string. This is usually
 * bad practice because manual construction could accidentally result in a SQL
 * injection. An attacker could use a SQL injection to steal or modify contents
 * of the database. Instead, use a parameterized query which is available
 * by default in most database engines. Alternatively, consider using an
 * object-relational mapper (ORM) such as Sequelize which will protect your queries.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/tainted-sql-string
 * @tags security
 *       external/cwe/cwe-89
 *       external/cwe/cwe-2021-top25
 *       external/cwe/cwe-2022-top25
 *       owasp-a01
 *       owasp-a03
 *       aws-lambda
 */

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class LambdaInputSource extends DataFlow::Node {
  LambdaInputSource() {
    exists(Method m, Parameter p |
      m.getName().matches("handleRequest%") and
      p = m.getAParameter() and
      (
        p.getType().hasName("InputStream") or
        p.getType().toString().matches("%$EVENT%")
      ) and
      this.asParameter() = p
    )
  }
}

class SqlStringSink extends DataFlow::Node {
  SqlStringSink() {
    exists(StringLiteral sql |
      sql.getValue().regexpMatch("(?i)(select|delete|insert|create|update|alter|drop)\\b") and
      this.asExpr() = sql
    )
    or
    exists(MethodCall mc |
      mc.getMethod().getName() = "concat" or
      mc.getMethod().getName() = "format" and
      this.asExpr() = mc
    )
    or
    exists(AddExpr ae | this.asExpr() = ae)
    or
    exists(MethodAccess ma |
      ma.getMethod().getName() = "append" and
      ma.getMethod().getDeclaringType().hasName("StringBuilder") and
      this.asExpr() = ma
    )
  }
}

class TaintedSqlStringConfiguration extends TaintTracking::Configuration {
  TaintedSqlStringConfiguration() { this = "TaintedSqlString" }

  override predicate isSource(DataFlow::Node source) { source instanceof LambdaInputSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlStringSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Call c | 
      c.getCallee().getName().matches("println%") and
      sanitizer.asExpr() = c
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedSqlStringConfiguration cfg
where cfg.hasFlowPath(source, sink)
select sink, "Detected user input used to manually construct a SQL string.", source, sink,
  "This is potentially vulnerable to SQL injection. Use parameterized queries instead."