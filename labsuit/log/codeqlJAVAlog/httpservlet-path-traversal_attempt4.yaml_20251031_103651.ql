/**
 * @name Path Traversal Vulnerability
 * @description Detected a potential path traversal. A malicious actor could control the location of this file.
 * @kind path-problem
 * @problem.severity error
 * @id java/path-traversal
 * @tags security
 *       external/cwe/cwe-22
 *       external/owasp/a05
 *       external/owasp/a01
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class HttpRequestSource extends DataFlow::Node {
  HttpRequestSource() {
    exists(Method m, Parameter p |
      m.getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      p = m.getAParameter() and
      this.asParameter() = p
    )
  }
}

class CookieSource extends DataFlow::Node {
  CookieSource() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getValue" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
      this.asExpr() = ma
    )
  }
}

class ArraySource extends DataFlow::Node {
  ArraySource() {
    exists(LocalVariableDecl lvd |
      lvd.getType() instanceof ArrayType and
      this.asExpr() = lvd.getAnAccess()
    )
  }
}

class FileConstructorSink extends DataFlow::Node {
  FileConstructorSink() {
    exists(Constructor c |
      c.getDeclaringType().hasQualifiedName("java.io", "File") and
      this.asExpr() = c.getAnInvocation()
    )
  }
}

class FileOutputStreamSink extends DataFlow::Node {
  FileOutputStreamSink() {
    exists(Constructor c |
      c.getDeclaringType().hasQualifiedName("java.io", "FileOutputStream") and
      this.asExpr() = c.getAnInvocation()
    )
  }
}

class FileInputStreamSink extends DataFlow::Node {
  FileInputStreamSink() {
    exists(Constructor c |
      c.getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and
      this.asExpr() = c.getAnInvocation()
    )
  }
}

class FilenameUtilsSanitizer extends TaintTracking::Sanitizer {
  FilenameUtilsSanitizer() {
    exists(Method m |
      m.hasQualifiedName("org.apache.commons.io", "FilenameUtils", "getName") and
      this.asExpr() = m.getACall()
    )
  }
}

class HttpPathTraversalConfig extends TaintTracking::Configuration {
  HttpPathTraversalConfig() { this = "HttpPathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof HttpRequestSource or
    source instanceof CookieSource or
    source instanceof ArraySource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileConstructorSink or
    sink instanceof FileOutputStreamSink or
    sink instanceof FileInputStreamSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma, Parameter p |
      ma.getMethod().getName() = "getParameter" and
      pred.asExpr() = ma and
      succ.asParameter() = p
    )
    or
    exists(ArrayAccess aa |
      pred.asExpr() = aa.getArray() and
      succ.asExpr() = aa
    )
  }
}

from HttpPathTraversalConfig cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential path traversal vulnerability from $@.", source, source.toString()