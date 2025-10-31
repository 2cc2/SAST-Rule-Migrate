/**
 * @name JDO SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL  
 * injection if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @id java/jdo-sqli
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.Expr

class SqlSource extends DataFlow::Node {
  SqlSource() {
    // String.format() calls
    exists(MethodAccess ma |
      ma.getMethod().hasName("format") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      this = ma.asExpr()
    )
    or
    // String concatenation assignments
    exists(AssignExpr ae |
      exists(AddExpr addExpr |
        addExpr = ae.getRight() and
        addExpr.getAnOperand() instanceof Expr
      ) and
      this = ae.getTarget().asExpr()
    )
    or
    // Parameters containing SQL
    exists(Parameter p |
      p.getName().matches("%SQL%") and
      this = p.asParameter()
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(MethodAccess ma |
      (
        (ma.getMethod().hasName("setFilter") or ma.getMethod().hasName("setGrouping")) and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "Query")
        or
        ma.getMethod().hasName("newQuery") and
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.jdo", "PersistenceManager")
      ) and
      this = ma.getAnArgument().asExpr()
    )
  }
}

class SafeAssignment extends DataFlow::Node {
  SafeAssignment() {
    exists(AssignExpr ae |
      ae.getRight().getType().hasName("java.lang.String") and
      ae.getRight().getAChildExpr*().isCompileTimeConstant() and
      this = ae.asExpr()
    )
  }
}

class SafeParameter extends DataFlow::Node {
  SafeParameter() {
    exists(Parameter p |
      p.getType().hasName("java.lang.String") and
      p.getAnAccess().getAChildExpr*().isCompileTimeConstant() and   
      this = p.asParameter()
    )
  }
}

class JdoSqlInjectionConfig extends TaintTracking::Configuration {
  JdoSqlInjectionConfig() { this = "JdoSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof SqlSource }
  
  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SafeAssignment or sanitizer instanceof SafeParameter
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("add%") and
      pred = ma.getAnArgument().asExpr() and
      succ = ma.asExpr()
    )
  }
}

from JdoSqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potentially unsafe SQL query construction"