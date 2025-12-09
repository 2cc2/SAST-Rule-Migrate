/**
 * @name Detected SQL injection in JDO queries
 * @description Detected a formatted string in a SQL statement. This could lead to 
 * SQL injection if variables in the SQL statement are not properly sanitized.
 * @kind problem
 * @problem.severity warning
 * @id java/jdo-sqli
 * @tags security
 *       external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.frameworks.jdo.JdoQueries

class SQLFormatSource extends TaintTracking::Source {
  SQLFormatSource() {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("format") and
      ma.getMethod().getDeclaringType().toString() = "String"
    )
  }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      source.asExpr() = ma and
      this.isSourceOf(_)
    )
  }
}

class SQLConcatSource extends TaintTracking::Source {
  SQLConcatSource() {
    exists(BinaryOperation bo |
      bo.getOperator().toString() = "+" and
      bo.getLeftOperand().toString().matches("%SQL%") and
      bo.getRightOperand().toString().matches("%SQL%")
    )
  }

  override predicate isSource(DataFlow::Node source) {
    exists(BinaryOperation bo |
      source.asExpr() = bo and
      this.isSourceOf(_)
    )
  }
}

class SQLParamSource extends TaintTracking::Source {
  SQLParamSource() {
    exists(Parameter p |
      p.getName().matches("%SQL%")
    )
  }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      source.asParameter() = p and
      this.isSourceOf(_)
    )
  }
}

class JDOQuerySink extends TaintTracking::Sink {
  JDOQuerySink() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "setFilter" or
       ma.getMethod().getName() = "setGrouping" or
       ma.getMethod().getName() = "newQuery") and
      ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("javax.jdo", "Query")
    )
  }

  override predicate sinks(DataFlow::Node sink) {
    exists(MethodAccess ma |
      sink.asExpr() = ma.getArgument(0) and
      this.sinks(_)
    )
  }
}

class SafeConcatSanitizer extends TaintTracking::Sanitizer {
  SafeConcatSanitizer() {
    exists(BinaryOperation bo |
      bo.getLeftOperand().isCompileTimeConstant() and
      bo.getRightOperand().isCompileTimeConstant()
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(BinaryOperation bo |
      node.asExpr() = bo and
      this.isSanitizer(node, _)
    )
  }
}

class SafeParamSanitizer extends TaintTracking::Sanitizer {
  SafeParamSanitizer() {
    exists(Parameter p |
      p.getCallable().getFile().getTotalNumberOfLines() > 0
    |
      p.getDefaultValue().isCompileTimeConstant()
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(Parameter p |
      node.asParameter() = p and
      this.isSanitizer(node, _)
    )
  }
}

class JdoSqlInjectionConfiguration extends TaintTracking::Configuration {
  JdoSqlInjectionConfiguration() { this = "JDO SQL Injection" }

  override predicate isSource(TaintTracking::Source source) {
    source instanceof SQLFormatSource or
    source instanceof SQLConcatSource or
    source instanceof SQLParamSource
  }

  override predicate isSink(TaintTracking::Sink sink) {
    sink instanceof JDOQuerySink
  }

  override predicate isSanitizer(TaintTracking::Sanitizer sanitizer) {
    sanitizer instanceof SafeConcatSanitizer or
    sanitizer instanceof SafeParamSanitizer
  }
}

from JdoSqlInjectionConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink,
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use prepared statements (java.sql.PreparedStatement) instead."