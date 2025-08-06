/**
 * @name XMLInputFactory External Entities Enabled
 * @description Detects when XML external entities are enabled for XMLInputFactory, making it vulnerable to XXE attacks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/xxe/xml-input-factory-external-entities-enabled
 * @tags security
 *       external/cwe/cwe-611
 *       external/owasp/a04:2017
 *       external/owasp/a05:2021
 *       external/asvs/4.0/5.5.2
 */
import java

from MethodAccess setPropertyCall, Expr arg1, Expr arg2
where
  setPropertyCall.getMethod().getName() = "setProperty" and
  setPropertyCall.getMethod().getDeclaringType().hasQualifiedName("javax.xml.stream", "XMLInputFactory") and
  (
    // Case 1: String literal with property name
    (
      arg1.toString() = "\"javax.xml.stream.isSupportingExternalEntities\"" and
      (arg2.toString() = "true" or arg2.toString() = "Boolean.TRUE")
    )
    or
    // Case 2: IS_SUPPORTING_EXTERNAL_ENTITIES constant
    (
      exists(FieldAccess fa | 
        fa.getField().getDeclaringType().hasQualifiedName("javax.xml.stream", "XMLInputFactory") and
        fa.getField().getName() = "IS_SUPPORTING_EXTERNAL_ENTITIES" and
        arg1 = fa
      ) and
      (arg2.toString() = "true" or arg2.toString() = "Boolean.TRUE")
    )
    or
    // Case 3: SUPPORT_DTD constant
    (
      exists(FieldAccess fa | 
        fa.getField().getDeclaringType().hasQualifiedName("javax.xml.stream", "XMLInputFactory") and
        fa.getField().getName() = "SUPPORT_DTD" and
        arg1 = fa
      ) and
      (arg2.toString() = "true" or arg2.toString() = "Boolean.TRUE")
    )
  )
select setPropertyCall, 
  "XML external entities are enabled for this XMLInputFactory. This is vulnerable to XML external entity attacks. Disable external entities by setting \"javax.xml.stream.isSupportingExternalEntities\" to false."