/**
 * @name Servlet Path Traversal
 * @description Detected a potential path traversal. A malicious actor could control the location of this file.
 * @severity error
 * @kind path-problem
 * @id java/servlet-path-traversal
 * @tags security
 *       external/cwe/cwe-22
 *       external/owasp/a05:2017
 *       external/owasp/a01:2021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class HttpRequestSource extends DataFlow::Node {
  HttpRequestSource() {
    exists(Method m, Parameter p |
      m.getName() = "getParameter" and
      m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
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
    exists(LocalVariableDecl lvd, ArrayType at |
      lvd.getType() = at and
      this.asExpr() = lvd.getVariable().getAnAccess()
    )
  }
}

class FileConstructorSink extends DataFlow::Node {
  FileConstructorSink() {
    exists(Constructor c |
      c.getDeclaringType().hasQualifiedName("java.io", "File") and
      this.asExpr() = c.getConstructorCall()
    )
  }
}

class FileOutputStreamSink extends DataFlow::Node {
  FileOutputStreamSink() {
    exists(Constructor c |
      c.getDeclaringType().hasQualifiedName("java.io", "FileOutputStream") and
      this.asExpr() = c.getConstructorCall()
    )
  }
}

class FileInputStreamSink extends DataFlow::Node {
  FileInputStreamSink() {
    exists(Constructor c |
      c.getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and
      this.asExpr() = c.getConstructorCall()
    )
  }
}

class FilenameUtilsSanitizer extends TaintTracking::Sanitizer {
  FilenameUtilsSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getName" and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      this.asExpr() = ma
    )
  }
}

class ServletPathTraversalConfig extends TaintTracking::Configuration {
  ServletPathTraversalConfig() { this = "ServletPathTraversalConfig" }

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

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof FilenameUtilsSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma, Parameter p |
      ma.getMethod().getName() = "getValue" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
      node1.asParameter() = p and
      node2.asExpr() = ma
    )
    or
    exists(ArrayAccess aa |
      node1.asExpr() = aa.getArray() and
      node2.asExpr() = aa
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink
where any(ServletPathTraversalConfig config).hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential path traversal vulnerability from $@.", source.getNode(), "user input"