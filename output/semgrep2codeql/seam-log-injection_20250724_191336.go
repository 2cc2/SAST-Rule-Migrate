/**
 * @name Seam Log Injection
 * @description Seam Logging API supports expression language to introduce bean property to log messages.
 *              The expression language can also be the source to unwanted code execution.
 *              In this context, an expression is built with a dynamic value.
 *              The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @problem.severity error
 * @id java/seam-log-injection
 * @tags security
 *       external/cwe/cwe-95
 *       external/owasp/a03:2021
 *       external/jboss
 */
import java

from MethodCall ma, AddExpr addExpr
where
  // Check method call matches log.{debug|error|fatal|info|trace|warn}($X + $Y,...)
  ma.getMethod().hasName(["debug", "error", "fatal", "info", "trace", "warn"]) and
  ma.getQualifier().getType().hasName("org.jboss.seam.log.Log") and
  addExpr = ma.getArgument(0)
select ma, "Seam Log injection vulnerability. User input should be properly sanitized " +
           "before being used in log expression to prevent code execution."