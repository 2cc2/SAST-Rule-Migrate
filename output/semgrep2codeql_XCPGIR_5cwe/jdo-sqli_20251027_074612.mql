/**
 * @name JDO SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection
 *              if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @id java/jdo-sqli
 * @tags security
 *       external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import DataFlow::PathGraph

class JdoSqlSource extends DataFlow::Node {
  JdoSqlSource() {
    // String.format() calls
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this.asExpr() = ma
    )
    or
    // Variables named SQL
    exists(Variable v |
      this.asExpr() = v.getAnAccess() and
      v.getType().hasName("String") and
      v.getName().matches("%SQL%")
    )
  }
}

class JdoSink extends DataFlow::Node {
  JdoSink() {
    exists(MethodAccess ma |
      (
        (ma.getMethod().hasName("setFilter") or ma.getMethod().hasName("setGrouping")) and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "Query") and
        this.asExpr() = ma.getArgument(0)
      )
      or
      (
        ma.getMethod().hasName("newQuery") and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "PersistenceManager") and
        this.asExpr() = ma.getArgument(0)
      )
    )
  }
}

class JdoSanitizer extends DataFlow::Node {
  JdoSanitizer() {
    this.asExpr() instanceof StringLiteral and
    this.asExpr().toString().matches("\"[^\"]+\"\\s*\\+\\s*\"[^\"]+\"")
  }
}

class JdoTaintConfig extends TaintTracking::Configuration {
  JdoTaintConfig() { this = "JDO SQL Injection" }

  override predicate isSource(DataFlow::Node source) { source instanceof JdoSqlSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof JdoSink }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof JdoSanitizer }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(AddExpr add |
      add.getAnOperand() = pred.asExpr() and
      add = succ.asExpr()
    )
  }
}

from JdoTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "User-provided SQL string reaches JDO query execution without proper sanitization"