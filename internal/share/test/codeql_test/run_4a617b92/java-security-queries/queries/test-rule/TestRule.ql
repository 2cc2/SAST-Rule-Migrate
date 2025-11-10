/**
 * @name JDBC SQL Injection in formatted string
 * @description Possible JDBC injection detected. Use the parameterized query
 *              feature available in queryForObject instead of concatenating or formatting strings:
 *              'jdbc.queryForObject("select * from table where name = ?", Integer.class, parameterName);'.
 * @kind problem
 * @id java/jdbc-sql-formatted-string
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class JdbcTemplateInitialization extends Expr {
  JdbcTemplateInitialization() {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate")
      and this = cc
    )
  }
}

class UnsafeQueryMethodCall extends MethodAccess {
  UnsafeQueryMethodCall() {
    exists(Method m | (
      m.hasName("queryForObject") or
      m.hasName("queryForList") or
      m.hasName("update") or
      m.hasName("execute") or
      m.hasName("insert")
    ) and
    m.getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
    this.getMethod() = m)
  }
}

class StringConcatenationExpr extends AddExpr {
  StringConcatenationExpr() {
    exists(Type t | this.getLeftOperand().getType() = t and t instanceof TypeString) or
    exists(Type t | this.getRightOperand().getType() = t and t instanceof TypeString)
  }
}

class StringFormatCall extends MethodAccess {
  StringFormatCall() {
    this.getMethod().hasQualifiedName("java.lang", "String", "format")
  }
}

class UnsafeStringConstruction extends Expr {
  UnsafeStringConstruction() {
    this instanceof StringConcatenationExpr or
    this instanceof StringFormatCall or
    exists(MethodAccess ma | 
      this = ma.getQualifier() and 
      ma instanceof AppendCall
    )
  }
}

class AppendCall extends MethodAccess {
  AppendCall() {
    this.getMethod().hasName("append") and
    this.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder")
  }
}

from UnsafeQueryMethodCall unsafeCall, Expr arg, DataFlow::Node source, DataFlow::Node sink
where
  arg = unsafeCall.getArgument(0) and 
  arg instanceof UnsafeStringConstruction and
  source.asExpr() = arg and sink.asExpr() = arg and
  DataFlow::localFlow(source, sink)
select unsafeCall,
  "Possible JDBC injection detected. Use the parameterized query feature instead of string concatenation.",
  unsafeCall,
  "Potential SQL injection vulnerability"