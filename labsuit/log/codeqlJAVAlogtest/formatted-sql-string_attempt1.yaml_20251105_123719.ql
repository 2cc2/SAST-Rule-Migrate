/**
 * @name Formatted SQL String
 * @description Detects a formatted string in a SQL statement.
 * @id formatted-sql-string
 * @kind path-problem
 * @security-severity 8.8
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

predicate isInputSource(DataFlow::Node source) {
  exists(MethodParameter p | 
    source.asParameter() = p and
    p.getType() instanceof TypeString and
    regexpMatch("\\$INPUT", p.getName())
  )
}

predicate isStringConcatCall(DataFlow::Node source) {
  exists(MethodAccess ma |
    source.asExpr() = ma and
    ma.getMethod().hasName(["concat", "append", "format", "join"]) and
    ma.getMethod().getDeclaringType().hasQualifiedName([
      "java.lang.String",
      "java.lang.StringBuilder",
      "java.lang.StringBuffer"
    ])
  )
}

predicate isSqlSink(DataFlow::Node sink) {
  exists(MethodAccess ma |
    sink.asExpr() = ma and
    ma.getMethod().hasName([
      "execute", "executeQuery", "createQuery", 
      "query", "addBatch", "nativeSQL", "create", "prepare"
    ]) and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.sql.Statement") and
    ma.getArgument(0) = sink.asExpr() and
    not regexpMatch(".*TABLE *$", ma.getArgument(0).toString()) and
    not regexpMatch(".*TABLE %s$", ma.getArgument(0).toString())
  )
}

predicate isSanitizer(DataFlow::Node node) {
  exists(MethodAccess ma |
    node.asExpr() = ma and
    ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence.criteria.CriteriaBuilder")
  )
}

class FormattedSqlStringConfig extends TaintTracking::Configuration {
  FormattedSqlStringConfig() { this = "FormattedSqlStringConfig" }

  override predicate isSource(DataFlow::Node source) {
    isInputSource(source) or isStringConcatCall(source)
  }

  override predicate isSink(DataFlow::Node sink) {
    isSqlSink(sink)
  }

  override predicate isSanitizer(DataFlow::Node node) {
    isSanitizer(node)
  }
}

from FormattedSqlStringConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.",
  source.getNode(), "User input flows into SQL query here"