/**
 * @name DefaultHttpClient is deprecated
 * @description DefaultHttpClient is deprecated and does not support TLS1.2 connections,
 *              making it a security hazard. Use HttpClientBuilder instead.
 * @kind problem
 * @problem.severity warning
 * @id java/default-http-client-deprecated
 * @tags security
 *       external/cwe/cwe-326
 *       external/owasp/a03:2017
 *       external/owasp/a02:2021
 *       asvs/V9.1.3
 */
import java

from Constructor c
where c.getDeclaringType().hasQualifiedName("org.apache.http.impl.client", "DefaultHttpClient")
select c, "DefaultHttpClient is deprecated and does not support TLS1.2. Use HttpClientBuilder instead."