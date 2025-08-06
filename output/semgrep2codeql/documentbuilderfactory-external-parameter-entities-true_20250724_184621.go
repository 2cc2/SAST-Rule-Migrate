/**
 * @name DocumentBuilderFactory external parameter entities true
 * @description Detects when DocumentBuilderFactory allows external parameter entities,
 *              which makes it vulnerable to XXE attacks.
 * @kind problem
 * @problem.severity error
 * @id java/documentbuilderfactory-external-parameter-entities-true
 * @tags security
 *       external/cwe/cwe-611
 *       external/owasp/a04:2017
 *       external/owasp/a05:2021
 */
import java

predicate isTargetDBF(MethodAccess ma) {
  exists(Method m |
    m = ma.getMethod() and
    m.hasName("setFeature") and
    m.getDeclaringType().hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory")
  )
}

from MethodAccess ma, StringLiteral feature, StringLiteral value
where
  isTargetDBF(ma) and
  feature = ma.getArgument(0) and
  feature.getValue() = "http://xml.org/sax/features/external-parameter-entities" and
  value = ma.getArgument(1) and
  value.getValue() = "true"
select ma, "External entities are allowed for DocumentBuilderFactory. This is vulnerable to XML external entity attacks. " +
  "Disable this by setting the feature \"http://xml.org/sax/features/external-parameter-entities\" to false."