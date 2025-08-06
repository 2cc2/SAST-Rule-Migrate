/**
 * @name Spring CSRF Protection Disabled
 * @description CSRF protection is disabled for this configuration. This is a security risk.
 * @kind problem
 * @id java/spring-csrf-disabled
 * @problem.severity warning
 * @security-severity 6.5
 * @precision low
 * @tags security
 *       external/cwe/cwe-352
 *       external/owasp/a01
 *       external/cwe2022-top25
 *       external/cwe2021-top25
 */
import java

from MethodAccess ma
where ma.getMethod().getName().matches("csrf") and
      ma.getMethod().getName().matches("disable")
select ma, "CSRF protection is disabled for this configuration. This is a security risk."