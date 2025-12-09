/**
 * @name Potential Path Traversal Vulnerability
 * @description Detected a potential path traversal. A malicious actor could control the location of this file.
 * @kind path-problem
 * @problem.severity error
 * @id java/path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       external/owasp/a05:2017
 *       external/owasp/a01:2021
 */
import java

// Sources
class HttpServletRequestSource extends MethodAccess {
  HttpServletRequestSource() {
    exists(Method m | m = this.getMethod() |
      m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
    )
  }
}

class CookieGetValueSource extends MethodAccess {
  CookieGetValueSource() {
    exists(Method m | m = this.getMethod() |
      m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
      m.getName() = "getValue"
    )
  }
}

class ParameterSource extends Parameter {
  ParameterSource() {
    this.getType() instanceof ArrayType
  }
}

// Sinks
class FileConstructorSink extends ClassInstanceExpr {
  FileConstructorSink() {
    exists(Constructor c | this.getConstructor() = c |
      c.getDeclaringType().hasQualifiedName("java.io", "File")
    )
  }
}

class FileOutputStreamSink extends ClassInstanceExpr {
  FileOutputStreamSink() {
    exists(Constructor c | this.getConstructor() = c |
      c.getDeclaringType().hasQualifiedName("java.io", "FileOutputStream")
    )
  }
}

class FileInputStreamSink extends ClassInstanceExpr {
  FileInputStreamSink() {
    exists(Constructor c | this.getConstructor() = c |
      c.getDeclaringType().hasQualifiedName("java.io", "FileInputStream")
    )
  }
}

// Sanitizers
class FilenameUtilsSanitizer extends MethodAccess {
  FilenameUtilsSanitizer() {
    exists(Method m | m = this.getMethod() |
      m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      m.getName() = "getName"
    )
  }
}

// Taint tracking configuration
class RequestPathTraversalConfig extends TaintTracking::Configuration {
  RequestPathTraversalConfig() { this = "RequestPathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asParameter() instanceof HttpServletRequestSource or
    source.asExpr() instanceof CookieGetValueSource or
    source.asParameter() instanceof ParameterSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof FileConstructorSink or
    sink.asExpr() instanceof FileOutputStreamSink or
    sink.asExpr() instanceof FileInputStreamSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() instanceof FilenameUtilsSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Propagation from request to cookie
    exists(MethodAccess ma | node1.asExpr() = ma.getArgument(0) and node2.asExpr() = ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie")
    ) or
    // Propagation through array elements
    exists(ArrayAccess aa | node1.asExpr() = aa.getArray() and node2.asExpr() = aa)
  }
}

from RequestPathTraversalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential path traversal. User input may control file path: $@.", source.getNode(),
  "user input flows here"