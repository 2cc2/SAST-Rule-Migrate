/**
 * @name JDO SQL Injection
 * @kind problem
 * @id java/jdo-sqli
 * @severity WARNING
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection
 *              if variables in the SQL statement are not properly sanitized. Use prepared statements
 *              (java.sql.PreparedStatement) instead.
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.jdo.JdoQueries

class SqlFormatSource extends DataFlow::Node {
  SqlFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("format") and
      ma.getMethod().getDeclaringType().toString() = "String" and
      this.asExpr() = ma
    )
  }
}

class SqlConcatSource extends DataFlow::Node {
  SqlConcatSource() {
    exists(AddExpr add |
      add.getLeftOperand().toString().matches("%SQL%") and
      this.asExpr() = add
    )
  }
}

class SqlParamSource extends DataFlow::Node {
  SqlParamSource() {
    exists(Variable v |
      v.getName().matches("%SQL%") and
      v instanceof Parameter and
      this.asVariable() = v
    )
  }
}

class SafeConcatSanitizer extends DataFlow::Node {
  SafeConcatSanitizer() {
    exists(AddExpr add |
      add.getLeftOperand().toString().matches("\".*\"") and
      add.getRightOperand().toString().matches("\".*\"") and
      this.asExpr() = add
    )
  }
}

class SafeParamSanitizer extends DataFlow::Node {
  SafeParamSanitizer() {
    exists(Variable v |
      v.getName().matches("\".*\"") and
      v instanceof Parameter and
      this.asVariable() = v
    )
  }
}

class JdoSink extends DataFlow::Node {
  JdoSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getName() = "setFilter" and
        ma.getMethod().getDeclaringType().getName() = "Query" and
        this.asExpr() = ma.getArgument(0)
      ) or
      (
        ma.getMethod().getName() = "setGrouping" and
        ma.getMethod().getDeclaringType().getName() = "Query" and
        this.asExpr() = ma.getArgument(0)
      ) or
      (
        ma.getMethod().getName() = "newQuery" and
        ma.getMethod().getDeclaringType().getName() = "PersistenceManager" and
        this.asExpr() = ma.getArgument(1)
      )
    )
  }
}

class JdoConfig extends TaintTracking::Configuration {
  JdoConfig() { this = "JDO SQL Injection" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlFormatSource or
    source instanceof SqlConcatSource or
    source instanceof SqlParamSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof JdoSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SafeConcatSanitizer or
    sanitizer instanceof SafeParamSanitizer
  }
}

from DataFlow::Node source, DataFlow::Node sink, JdoConfig config
where config.hasFlow(source, sink)
select sink, "Detected a formatted string in a SQL statement. This could lead to SQL injection "
       "if variables in the SQL statement are not properly sanitized. Use prepared statements "
       "(java.sql.PreparedStatement) instead."