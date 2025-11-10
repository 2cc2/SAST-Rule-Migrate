/**
 * @name Insecure RESTEasy Deserialization
 * @description When a Restful webservice endpoint is configured to use wildcard media type as a value for the
 * @Consumes annotation, or uses application/x-java-serialized-object, it may lead to deserialization vulnerabilities.
 * @kind problem
 * @id java/insecure-resteasy-deserialization
 * @tags security
 *       external/cwe/cwe-502
 *       owasp-a08:2017
 *       owasp-a08:2021
 */
import java

predicate isInsecureConsumes(Annotation a) {
  a.toString().matches("@Consumes\\(.*application/x-java-serialized-object.*\\)") or
  a.toString().matches("@Consumes\\(.*\\*/\\*.*\\)") or
  a.toString().matches("@Consumes\\(.*MediaType\\.WILDCARD_TYPE.*\\)")
}

from Annotation consumes, Method m
where 
  isInsecureConsumes(consumes) and
  consumes.getTarget() = m
select consumes, "Potential insecure RESTEasy deserialization with @Consumes annotation"