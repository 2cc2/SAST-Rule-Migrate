/**
 * @name SAXParserFactory XXE Vulnerability
 * @description DOCTYPE declarations are enabled for SAXParserFactory, making it vulnerable to XXE attacks.
 *              Disable by setting feature http://apache.org/xml/features/disallow-doctype-decl to true,
 *              or set http://xml.org/sax/features/external-general-entities and 
 *              http://xml.org/sax/features/external-parameter-entities to false.
 * @kind path-problem
 * @problem.severity error
 * @id java/saxparserfactory-xxe
 * @tags security
 *       external/cwe/cwe-611
 *       external/owasp/a04
 *       external/owasp/a05
 */

import java
import semmle.code.java.dataflow.TaintTracking

class SAXParserFactorySource extends DataFlow::Node {
  SAXParserFactorySource() {
    exists(Call ma |
      ma.getCallee().hasName("newInstance") and
      ma.getCallee().getDeclaringType().hasQualifiedName("javax.xml.parsers", "SAXParserFactory") and
      this.asExpr() = ma
    )
  }
}

class SAXParserFactorySink extends DataFlow::Node {
  SAXParserFactorySink() {
    exists(Call ma |
      ma.getCallee().hasName("newSAXParser") and
      ma.getCallee().getDeclaringType().hasQualifiedName("javax.xml.parsers", "SAXParserFactory") and
      this.asExpr() = ma
    )
  }
}

predicate isSecureConfiguration(Expr factory) {
  exists(Call setFeature |
    setFeature.getCallee().hasName("setFeature") and
    setFeature.getQualifier() = factory and
    (
      setFeature.getArgument(0).toString() = "\"http://apache.org/xml/features/disallow-doctype-decl\"" and
      setFeature.getArgument(1).toString() = "true"
      or
      (
        setFeature.getArgument(0).toString() = "\"http://xml.org/sax/features/external-general-entities\"" and
        setFeature.getArgument(1).toString() = "false" and
        exists(Call setFeature2 |
          setFeature2.getCallee().hasName("setFeature") and
          setFeature2.getQualifier() = factory and
          setFeature2.getArgument(0).toString() = "\"http://xml.org/sax/features/external-parameter-entities\"" and
          setFeature2.getArgument(1).toString() = "false"
        )
      )
    )
  )
}

class SAXParserFactoryConfig extends TaintTracking::Configuration {
  SAXParserFactoryConfig() { this = "SAXParserFactoryConfig" }

  override predicate isSource(DataFlow::Node source) { 
    source instanceof SAXParserFactorySource and
    not isSecureConfiguration(source.asExpr())
  }

  override predicate isSink(DataFlow::Node sink) { 
    sink instanceof SAXParserFactorySink 
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) { 
    isSecureConfiguration(sanitizer.asExpr())
  }
}

from SAXParserFactoryConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SAXParserFactory is vulnerable to XXE attacks. Disable DOCTYPE declarations or external entities."