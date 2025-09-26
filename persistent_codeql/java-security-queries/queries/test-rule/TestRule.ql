/**
 * @name Tainted HTML string
 * @description Detected user input flowing into a manually constructed HTML string.
 *              This could create a cross-site scripting vulnerability, which could let
 *              attackers steal sensitive user data.
 * @kind path-problem
 * @problem.severity error
 * @id java/tainted-html-string
 * @tags security
 *       external/cwe/cwe-79
 *       external/owasp/a07:2017
 *       external/owasp/a03:2021
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.StringFormat
import semmle.code.java.frameworks.spring.SpringController

class HtmlStringTaintConfig extends TaintTracking::Configuration {
  HtmlStringTaintConfig() { this = "HtmlStringTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m, Parameter p |
      p = m.getAParameter() and
      source.asParameter() = p and
      (
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestHeader") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "CookieValue") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "ModelAttribute")
      ) and
      not p.getType() instanceof PrimitiveType
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Method m, Call ma |
      (
        m.hasQualifiedName("org.springframework.http", "ResponseEntity", "<init>") or
        m.hasQualifiedName("org.springframework.http", "ResponseEntity", "body")
      ) and
      ma.getCallee() = m and
      sink.asExpr() = ma.getArgument(0) and
      isHtmlStringConstruction(ma.getArgument(0))
    )
  }

  predicate isHtmlStringConstruction(Expr e) {
    exists(AddExpr add |
      add.getLeftOperand().toString().matches("^<\\w+") and
      add.getRightOperand() = e
    )
    or
    exists(Method m, Call ma |
      m.hasName("concat") and
      ma.getCallee() = m and
      ma.getQualifier().toString().matches("^<\\w+") and
      ma.getArgument(0) = e
    )
    or
    exists(Method m, Call ma |
      m.hasName("append") and
      m.getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      ma.getCallee() = m and
      exists(LocalVariableDecl lvd |
        lvd.getInitializer().toString().matches("^<\\w+") and
        lvd.getAnAccess() = ma.getQualifier()
      ) and
      ma.getArgument(0) = e
    )
    or
    exists(AssignAddExpr aae |
      aae.getLhs() = e and
      exists(LocalVariableDecl lvd |
        lvd.getInitializer().toString().matches("^<\\w+") and
        lvd.getAnAccess() = aae.getLhs()
      )
    )
    or
    exists(Method m, Call ma |
      m.hasName("format") and
      m.getDeclaringType().hasQualifiedName("java.lang", "String") and
      ma.getCallee() = m and
      ma.getArgument(0).toString().matches("^<\\w+") and
      ma.getAnArgument() = e
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Method m, Call ma |
      (
        m.hasQualifiedName("org.owasp.esapi", "Encoder", "forHtml") or
        m.hasQualifiedName("org.owasp.html", "PolicyFactory", "sanitize") or
        m.hasQualifiedName("org.owasp.validator.html", "AntiSamy", "scan") or
        m.hasQualifiedName("org.jsoup", "Jsoup", "clean")
      ) and
      ma.getCallee() = m and
      sanitizer.asExpr() = ma
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Method m, Call ma |
      m.hasName("append") and
      m.getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
      ma.getCallee() = m and
      ma.getArgument(0) = node1.asExpr() and
      node2.asExpr() = ma.getQualifier()
    )
    or
    exists(AssignAddExpr aae |
      aae.getLhs() = node1.asExpr() and
      node2.asExpr() = aae
    )
  }
}

from HtmlStringTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Potential XSS vulnerability: user input flows into HTML string construction", 
  source, "User input source"