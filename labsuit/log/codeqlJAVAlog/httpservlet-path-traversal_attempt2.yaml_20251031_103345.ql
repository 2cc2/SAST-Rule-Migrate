/**
 * @name Potential Path Traversal
 * @description Detected a potential path traversal. A malicious actor could control the location of this file,
 * to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables
 * in file paths are sanitized.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id java/path-traversal
 * @tags security
 *       external/cwe/cwe-022
 *       external/owasp/a05:2017
 *       external/owasp/a01:2021
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class HttpServletRequestSource extends DataFlow::SourceNode {
  HttpServletRequestSource() {
    exists(MethodFacade m |
      result.asParameter() = m.getParameter(_) |
      m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
    )
  }
}

class CookieGetValueSource extends DataFlow::SourceNode {
  CookieGetValueSource() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getValue") and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
      result.asExpr() = ma
    )
  }
}

class ParameterSource extends DataFlow::SourceNode {
  ParameterSource() {
    result.asParameter().getType() instanceof Array
  }
}

class FileConstructorSink extends DataFlow::SinkNode {
  FileConstructorSink() {
    exists(ConstructorCall cc |
      cc.getConstructor().getDeclaringType().hasQualifiedName("java.io", "File") and
      result.asExpr() = cc
    )
  }
}

class FileOutputStreamSink extends DataFlow::SinkNode {
  FileOutputStreamSink() {
    exists(ConstructorCall cc |
      cc.getConstructor().getDeclaringType().hasQualifiedName("java.io", "FileOutputStream") and
      result.asExpr() = cc
    )
  }
}

class FileInputStreamSink extends DataFlow::SinkNode {
  FileInputStreamSink() {
    exists(ConstructorCall cc |
      cc.getConstructor().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and
      result.asExpr() = cc
    )
  }
}

class FilenameUtilsSanitizer extends TaintTracking::Sanitizer {
  FilenameUtilsSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getName") and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      this.asExpr() = ma
    )
  }
}

class RequestPathTraversalConfig extends TaintTracking::Configuration {
  RequestPathTraversalConfig() { this = "RequestPathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof HttpServletRequestSource or
    source instanceof CookieGetValueSource or
    source instanceof ParameterSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileConstructorSink or
    sink instanceof FileOutputStreamSink or
    sink instanceof FileInputStreamSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof FilenameUtilsSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma, Parameter p |
      ma.getMethod().getName() = "getValue" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
      succ.asExpr() = ma and
      pred.asParameter() = p and
      ma.getArgument(0) = p.getAnAccess()
    )
    or
    exists(ArrayAccess aa |
      succ.asExpr() = aa and
      pred = aa.getArray()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, RequestPathTraversalConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential path traversal from $@ to $@", source.getNode(),
  "user input", sink.getNode(), "file operation"