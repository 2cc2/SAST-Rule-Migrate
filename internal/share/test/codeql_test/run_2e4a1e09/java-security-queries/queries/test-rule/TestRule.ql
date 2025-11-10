/**
 * @name Tainted File Path
 * @description Detected user input controlling a file path. An attacker could control the location of this
 *              file, to include going backwards in the directory with '../'.
 * @kind path-problem
 * @problem.severity error
 * @id java/tainted-file-path
 * @tags security
 *       external/cwe/cwe-23
 *       external/owasp/a01
 *       external/codeql/java
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.spring.SpringController

class RequestAnnotation extends Annotation {
  RequestAnnotation() {
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody") or
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") or
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") or
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestHeader") or
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "CookieValue") or
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "ModelAttribute")
  }
}

class SourceNode extends DataFlow::Node {
  SourceNode() {
    exists(Method m, Parameter p, RequestAnnotation a |
      m.getAParameter() = p and
      p.getAnAnnotation() = a and
      not p.getType().toString().matches("^(Integer|Long|Float|Double|Char|Boolean|int|long|float|double|char|boolean)") and
      this.asParameter() = p
    )
  }
}

class SinkNode extends DataFlow::Node {
  SinkNode() {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "File") and
      this.asExpr() = cc
    )
    or
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "FileReader") and
      this.asExpr() = cc
    )
    or
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "FileInputStream") and
      this.asExpr() = cc
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().getName() = "get" and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") and
      this.asExpr() = ma
    )
    or
    exists(MethodAccess ma |
      (ma.getMethod().getName() = "getResource" or ma.getMethod().getName() = "getResourceAsStream") and
      this.asExpr() = ma
    )
    or
    exists(Expr arg |
      (exists(ConstructorCall cc |
        cc.getConstructedType().hasQualifiedName("org.springframework.core.io", "ClassPathResource") and
        cc.getArgument(0) = arg
      )
      or
      exists(MethodAccess ma |
        ma.getMethod().hasQualifiedName("org.springframework.util", "ResourceUtils", "getFile") and
        ma.getArgument(0) = arg
      )
      or
      exists(ConstructorCall cc |
        cc.getConstructedType().hasQualifiedName("java.io", "FileOutputStream") and
        cc.getArgument(0) = arg
      )
      or
      exists(ConstructorCall cc |
        cc.getConstructedType().hasQualifiedName("javax.xml.transform.stream", "StreamSource") and
        cc.getArgument(0) = arg
      )
      or
      exists(MethodAccess ma |
        ma.getMethod().hasQualifiedName("org.apache.commons.io", "FileUtils", "openOutputStream") and
        ma.getArgument(0) = arg
      )) and
      this.asExpr() = arg
    )
  }
}

class Sanitizer extends DataFlow::Node {
  Sanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("org.apache.commons.io", "FilenameUtils", "getName") and
      this.asExpr() = ma
    )
  }
}

class TaintedFileConfig extends TaintTracking::Configuration {
  TaintedFileConfig() { this = "TaintedFileConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof SourceNode }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SinkNode }

  override predicate isSanitizer(DataFlow::Node sanitizer) { sanitizer instanceof Sanitizer }
}

from TaintedFileConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential path traversal vulnerability from user-controlled input"