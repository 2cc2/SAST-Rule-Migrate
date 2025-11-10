/**
 * @name DocumentBuilderFactory with DOCTYPE declarations enabled
 * @description DOCTYPE declarations are enabled for this DocumentBuilderFactory. This
 *              is vulnerable to XML external entity attacks. Disable this by setting the
 *              feature "http://apache.org/xml/features/disallow-doctype-decl" to true.
 * @id documentbuilderfactory-disallow-doctype-decl-missing
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security
 *       java
 *       xml
 *       owasp-a4
 *       owasp-a5
 *       external/cwe/cwe-611
 */

import java
import semmle.code.java.dataflow.TaintTracking

class DocumentBuilderFactoryCreation extends Call {
  DocumentBuilderFactoryCreation() {
    exists(Method m |
      m.hasName("newInstance") and
      m.getDeclaringType().hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory") and
      this.getCallee() = m
    )
  }
}

class SafeFeatureConfig extends Call {
  SafeFeatureConfig() {
    exists(string feature |
      feature = "http://apache.org/xml/features/disallow-doctype-decl" and
      this.getCallee().hasName("setFeature") and
      this.getArgument(0).toString() = feature and
      this.getArgument(1).toString() = "true"
    )
    or
    exists(string genEntities, string paramEntities |
      genEntities = "http://xml.org/sax/features/external-general-entities" and
      paramEntities = "http://xml.org/sax/features/external-parameter-entities" and
      this.getCallee().hasName("setFeature") and
      ((this.getArgument(0).toString() = genEntities and this.getArgument(1).toString() = "false")
       or
       (this.getArgument(0).toString() = paramEntities and this.getArgument(1).toString() = "false"))
    )
  }
}

class DocumentBuilderFactoryTaintConfig extends TaintTracking::Configuration {
  DocumentBuilderFactoryTaintConfig() { this = "DocumentBuilderFactoryTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(DocumentBuilderFactoryCreation dbc, LocalVariableDecl factory |
      dbc.getEnclosingCallable() = factory.getEnclosingCallable() and
      (
        source.asExpr() = factory.getAnAccess() or
        source.asExpr() = dbc
      ) and
      not exists(SafeFeatureConfig config |
        config.getEnclosingCallable() = factory.getEnclosingCallable() and
        factory.getAnAccess() = config.getQualifier()
      )
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call ma, Method m |
      ma.getCallee() = m and
      m.hasName("newDocumentBuilder") and
      m.getDeclaringType().hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory") and
      sink.asExpr() = ma
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, DocumentBuilderFactoryTaintConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source.getNode(), 
  "DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks.",
  "Enable disallow-doctype-decl or disable external entities features."