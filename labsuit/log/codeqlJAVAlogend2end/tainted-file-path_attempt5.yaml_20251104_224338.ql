/**
 * @name Tainted file path
 * @description Detected user input controlling a file path. An attacker could control the location of this
 *    file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled
 *    variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...)
 *    to only retrieve the file name from the path.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/tainted-file-path
 * @tags security
 *       external/cwe/cwe-023
 *       owasp-a1
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.frameworks.spring.SpringRequest
import DataFlow::PathGraph

class TaintedFileConfig extends DataFlow::Configuration {
  TaintedFileConfig() { this = "Tainted file path configuration" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method method, Parameter parameter |
      parameter = method.getAParameter() and
      SpringRequest::requestParamAnnotation(parameter) and
      not parameter.getType() instanceof PrimitiveType and
      not parameter.getType() instanceof BoxedType and
      source.asParameter() = parameter
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Constructor file |
      file.getDeclaringType().hasQualifiedName("java.io", "File") and
      sink.asExpr() = file.getAnArgument()
    )
    or
    exists(Constructor fileReader |
      fileReader.getDeclaringType().hasQualifiedName("java.io", "FileReader") and
      sink.asExpr() = fileReader.getAnArgument()
    )
    or
    exists(Constructor fileInputStream |
      fileInputStream.getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and
      sink.asExpr() = fileInputStream.getAnArgument()
    )
    or
    exists(Method pathsGet |
      pathsGet.hasQualifiedName("java.nio.file", "Paths", "get") and
      sink.asExpr() = pathsGet.getACall().getArgument(0)
    )
    or
    exists(Method classResource |
      (classResource.hasQualifiedName("java.lang", "Class", "getResource") or
       classResource.hasQualifiedName("java.lang", "Class", "getResourceAsStream")) and
      sink.asExpr() = classResource.getACall().getArgument(0)
    )
    or
    exists(Method fileOperation |
      (fileOperation.hasQualifiedName("org.springframework.util", "ResourceUtils", "getFile") or
       fileOperation.hasQualifiedName("org.apache.commons.io", "FileUtils", "openOutputStream")) and
      sink.asExpr() = fileOperation.getACall().getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(Method getName |
      getName.hasQualifiedName("org.apache.commons.io", "FilenameUtils", "getName") and
      sanitizer.asExpr() = getName.getACall()
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, TaintedFileConfig config
where config.hasFlowPath(source, sink)
select sink, "Potential path traversal vulnerability from user-controllable source $@.", source,
  "User input flows into file path operation"