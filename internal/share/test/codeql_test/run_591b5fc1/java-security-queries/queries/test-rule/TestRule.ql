/**
 * @name Unrestricted Request Mapping
 * @description Detected a method annotated with 'RequestMapping' that does not specify
 * the HTTP method. CSRF protections are not enabled for GET, HEAD, TRACE,
 * or OPTIONS, and by default all HTTP methods are allowed when the HTTP method
 * is not explicitly specified. This means that a method that performs state
 * changes could be vulnerable to CSRF attacks. To mitigate, add the 'method'
 * field and specify the HTTP method (such as 'RequestMethod.POST').
 * @kind problem
 * @problem.severity warning
 * @id java/unrestricted-request-mapping
 * @tags security
 *       external/cwe/cwe-352
 *       external/owasp/a01:2021
 *       cwe2022-top25
 *       cwe2021-top25
 */

import java

from Method m, Annotation a
where
  a = m.getAnAnnotation() and
  a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping") and
  not exists(Expr arg |
    arg = a.getValue("method")
  )
select m, "Detected a method annotated with 'RequestMapping' that does not specify the HTTP method, potentially vulnerable to CSRF attacks."