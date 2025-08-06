/**
 * @name Tainted HTML String
 * @description Detects user input flowing into a manually constructed HTML string.
 *              This could create a cross-site scripting vulnerability if the HTML
 *              is not rendered safely.
 * @kind path-problem
 * @problem.severity error
 * @id java/tainted-html-string
 * @tags security
 *       external/cwe/cwe-79
 *       external/owasp/a07
 *       external/owasp/a03
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.spring.SpringRequest
import semmle.code.java.StringOps

class HtmlInputSource extends DataFlow::Node {
  HtmlInputSource() {
    exists(Method m, Parameter p |
      m.getAnAnnotation().getType().getName() in [
        "RequestBody", "PathVariable", "RequestParam", 
        "RequestHeader", "CookieValue", "ModelAttribute"
      ] and
      p = m.getAParameter() and
      not p.getType().hasName([
        "Integer","Long","Float","Double","Char","Boolean",
        "int","long","float","double","char","boolean"
      ]) and
      this.asParameter() = p
    ) 
  }
}

class HtmlStringLiteral extends DataFlow::Node {
  HtmlStringLiteral() {
    exists(StringLiteral sl |
      sl.getText().regexpMatch("^<\\w+") and
      this.asExpr() = sl
    )
  }
}

class HtmlConcatenation extends DataFlow::Node {
  HtmlConcatenation() {
    exists(AddExpr add |
      add.getLeftOperand().(StringLiteral).getText().regexpMatch("^<\\w+") and
      this.asExpr() = add
    ) or
    exists(MethodAccess concat |
      concat.getMethod().hasName("concat") and
      concat.getQualifier().(StringLiteral).getText().regexpMatch("^<\\w+") and
      this.asExpr() = concat
    ) or
    exists(MethodAccess append, StringLiteral sl |
      append.getMethod().hasName("append") and
      append.getQualifier().getType().hasName("StringBuilder") and
      sl.getText().regexpMatch("^<\\w+") and
      sl = append.getQualifier().getAValue() and
      this.asExpr() = append
    )
  }
}

class HtmlSink extends DataFlow::Node {
  HtmlSink() {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("org.springframework.http", "ResponseEntity") and
      this.asExpr() = cc.getArgument(0)
    ) or
    exists(Call bodyCall |
      bodyCall.getCallee().hasName("body") and
      bodyCall.getCallee().getDeclaringType().hasQualifiedName("org.springframework.http", "ResponseEntity") and
      this.asExpr() = bodyCall.getArgument(0)  
    )
  }
}

class HtmlSanitizer extends DataFlow::Node {
  HtmlSanitizer() {
    exists(Call sanitizeCall |
      sanitizeCall.getCallee().hasName("forHtml") and
      sanitizeCall.getCallee().getDeclaringType().hasQualifiedName("org.owasp.esapi", "Encoder")
    ) or
    exists(Call sanitizeCall |
      sanitizeCall.getCallee().hasName("sanitize") and
      sanitizeCall.getCallee().getDeclaringType().hasQualifiedName("org.owasp.html", "PolicyFactory") 
    )
  }
}

class HtmlTaintConfig extends TaintTracking::Configuration {
  HtmlTaintConfig() { this = "HtmlTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof HtmlInputSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof HtmlSink and
    exists(DataFlow::Node html |
      html instanceof HtmlStringLiteral or 
      html instanceof HtmlConcatenation |
      TaintTracking::localTaint(html, sink)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof HtmlSanitizer
  }
}

from HtmlTaintConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, source, sink,
  "Detected user input flowing into a manually constructed HTML string. This could create a cross-site scripting vulnerability."