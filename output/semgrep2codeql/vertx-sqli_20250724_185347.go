/**
 * @name vertx-sqli
 * @description Detected a formatted string in a SQL statement. This could lead to SQL
 * injection if variables in the SQL statement are not properly sanitized.
 * Use a prepared statements (java.sql.PreparedStatement) instead.
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id java/vertx-sqli
 * @tags security
 *       external/cwe/cwe-89
 *       external/cwe/cwe-2021-top25
 *       external/cwe/cwe-2022-top25
 *       external/owasp/a01:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.StringFormat

predicate isSuspiciousSqlConstruction(Expr e) {
  exists(AddExpr add | add = e | // String concatenation
    not add.getRightOperand().isCompileTimeConstant() or
    not add.getLeftOperand().isCompileTimeConstant())
  or
  exists(MethodAccess format | format.getMethod().getName().matches("format") and format = e)
}

from MethodAccess ma, Expr db
where
  // Method matches suspicious names
  (ma.getMethod().getName().matches("%query%") or
  ma.getMethod().getName().matches("%preparedQuery%") or
  ma.getMethod().getName().matches("%prepare%")) and
  // Receiver is database access
  ma.getQualifier() = db and
  // Argument is suspicious SQL construction
  exists(Expr sqlArg |
    sqlArg = ma.getArgument(0) and
    isSuspiciousSqlConstruction(sqlArg)
  )
select ma, "Detected a formatted string in a SQL statement. This could lead to SQL injection. " +
  "Use prepared statements (java.sql.PreparedStatement) instead."