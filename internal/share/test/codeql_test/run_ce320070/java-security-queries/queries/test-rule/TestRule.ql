/**
 * @name XMLInputFactory Possible XXE
 * @description XML external entities are not explicitly disabled for XMLInputFactory.
 *              This could be vulnerable to XML external entity vulnerabilities.
 * @kind path-problem
 * @problem.severity warning
 * @id java/xmlinputfactory-possible-xxe
 * @tags security
 *       external/cwe/cwe-611
 *       external/owasp/a04
 *       external/owasp/a05
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class XMLInputFactoryCreation extends DataFlow::Node {
  XMLInputFactoryCreation() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "newFactory" and
       ma.getMethod().getDeclaringType().hasQualifiedName("javax.xml.stream", "XMLInputFactory")) or
      (ma.getMethod().getName() = "<init>" and
       ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.stream", "XMLInputFactory")) and
      this.asExpr() = ma
    )
  }
}

class XMLInputFactoryProperty extends DataFlow::Node {
  XMLInputFactoryProperty() {
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "setProperty" and
       ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.stream", "XMLInputFactory")) and
      (
        (ma.getArgument(0).toString() = "\"javax.xml.stream.isSupportingExternalEntities\"" and
         (ma.getArgument(1).toString() = "false" or ma.getArgument(1).toString() = "Boolean.FALSE")) or
        (ma.getArgument(0).toString() = "javax.xml.stream.XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES" and
         (ma.getArgument(1).toString() = "false" or ma.getArgument(1).toString() = "Boolean.FALSE"))
      ) and
      this.asExpr() = ma.getQualifier()
    )
  }
}

class XXEConfig extends TaintTracking::Configuration {
  XXEConfig() { this = "XXEConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof XMLInputFactoryCreation }

  override predicate isSink(DataFlow::Node sink) { not exists(XMLInputFactoryProperty prop | prop = sink) }

  override predicate isSanitizer(DataFlow::Node sanitizer) { none() }
}

from XXEConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "XML external entities are not explicitly disabled for this XMLInputFactory. " +
"This could be vulnerable to XML external entity vulnerabilities. " +
"Explicitly disable external entities by setting \"javax.xml.stream.isSupportingExternalEntities\" to false."