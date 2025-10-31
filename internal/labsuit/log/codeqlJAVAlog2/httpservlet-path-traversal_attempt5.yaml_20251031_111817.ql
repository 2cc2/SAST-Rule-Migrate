/**
 * @name Potential Path Traversal
 * @kind problem
 * @id java/path-traversal
 * @severity error
 * @security-severity 8.0
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class HttpServletRequestSource extends DataFlow::ParameterNode {
  HttpServletRequestSource() {
    exists(Method m, ParameterNode p |
      m.getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      p = m.getAParameter() and
      this = p
    )
  }
}

class CookieGetValueSource extends DataFlow::Node {
  CookieGetValueSource() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getValue" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
      this.asExpr() = ma
    )
  }
}

class ArrayLocalSource extends DataFlow::Node {
  ArrayLocalSource() {
    exists(LocalVariableDecl v |
      v.getType() instanceof ArrayType and
      this = v.getAChildExpr()
    )
  }
}

class FileOperationsSink extends DataFlow::Node {
  FileOperationsSink() {
    exists(MethodAccess ma |
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileInputStream") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "FileOutputStream")
      ) and
      this.asExpr() = ma
    )
  }
}

class FilenameUtilsSanitizer extends DataFlow::Node {
  FilenameUtilsSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "getName" and
      ma.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
      this.asExpr() = ma
    )
  }
}

class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() { this = "PathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof HttpServletRequestSource or
    source instanceof CookieGetValueSource or
    source instanceof ArrayLocalSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileOperationsSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof FilenameUtilsSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodAccess ma | 
      ma.getMethod().getName() = "getValue" and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
      pred.asExpr() = ma.getAnArgument() and
      succ.asExpr() = ma
    ) or
    exists(ArrayAccess aa |
      pred.asExpr() = aa.getArray() and
      succ.asExpr() = aa.getAnAccess()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, PathTraversalConfig ptc
where ptc.hasFlowPath(source, sink)
select sink.getNode(), source.getNode(), 
  "Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.",
  source.getNode(), "User input"