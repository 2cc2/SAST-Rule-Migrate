/**
 * @name DocumentBuilderFactory disallow doctype decl false
 * @description Detects when DocumentBuilderFactory allows DOCTYPE declarations without proper
 *              XML External Entity (XXE) protection measures.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/xxe/documentbuilderfactory-disallow-doctype-decl-false
 * @tags security
 *       external/cwe/cwe-611
 *       external/cwe/cwe-827
 *       external/owasp/a04
 *       external/owasp/a05
 */
import java

from MethodCall setFeatureCall
where
  setFeatureCall.getMethod().hasName("setFeature") and
  setFeatureCall.getArgument(0).toString() = "\"http://apache.org/xml/features/disallow-doctype-decl\"" and
  setFeatureCall.getArgument(1).toString() = "false" and
  not exists(
    MethodCall mc1, MethodCall mc2 |
    mc1.getMethod().hasName("setFeature") and
    mc1.getArgument(0).toString() = "\"http://xml.org/sax/features/external-general-entities\"" and
    mc1.getArgument(1).toString() = "false" and
    mc2.getMethod().hasName("setFeature") and
    mc2.getArgument(0).toString() = "\"http://xml.org/sax/features/external-parameter-entities\"" and
    mc2.getArgument(1).toString() = "false" and
    mc1.getEnclosingCallable() = mc2.getEnclosingCallable() and
    mc1.getEnclosingCallable() = setFeatureCall.getEnclosingCallable()
  ) and
  not exists(
    MethodCall mc3, MethodCall mc4 |
    mc3.getMethod().hasName("setAttribute") and
    mc3.getArgument(0).toString() = "XMLConstants.ACCESS_EXTERNAL_DTD" and
    mc3.getArgument(1).toString() = "\"\"" and
    mc4.getMethod().hasName("setAttribute") and
    mc4.getArgument(0).toString() = "XMLConstants.ACCESS_EXTERNAL_SCHEMA" and
    mc4.getArgument(1).toString() = "\"\"" and
    mc3.getEnclosingCallable() = mc4.getEnclosingCallable() and
    mc3.getEnclosingCallable() = setFeatureCall.getEnclosingCallable()
  )
select setFeatureCall,
  "DOCTYPE declarations are enabled for DocumentBuilderFactory. Without prohibiting external entity declarations, this is vulnerable to XML external entity attacks. " +
  "Disable this by setting the feature 'http://apache.org/xml/features/disallow-doctype-decl' to true. " +
  "Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations by setting " +
  "'http://xml.org/sax/features/external-general-entities' and 'http://xml.org/sax/features/external-parameter-entities' to false."