/**
 * @name XSSRequestWrapper is insecure
 * @description Detects usage of insecure XSSRequestWrapper implementation from dzone.
 *              The XSS filtering in this code is not secure and can be bypassed.
 * @kind problem
 * @problem.severity warning
 * @id java/xss-request-wrapper-is-insecure
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-2021-top25
 *       external/cwe/cwe-2022-top25
 *       owasp-a03
 *       owasp-a07
 */
import java

// Match class extending XSSRequestWrapper
from Class cls
where 
  cls.getASupertype*().hasName("HttpServletRequestWrapper") and
  cls.getName().matches("XSSRequestWrapper")
select cls, "Insecure implementation of XSSRequestWrapper detected. Consider using a stack that automatically escapes in your view/templates."