/**
 * @name pg8000-sqli
 * @description Detected string concatenation with a non-literal variable in a pg8000 Python SQL statement. 
 *              This could lead to SQL injection if the variable is user-controlled and not properly sanitized. 
 *              In order to prevent SQL injection, use parameterized queries or prepared statements instead.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @cwe 89
 * @security-severity 7.5
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */
import python
import DataFlow::PathGraph

class SqlSource extends DataFlow::Node {
  SqlSource() {
    exists(DataFlow::AssignmentNode assign |
      assign.getRight().getValue().regexpMatch(".*\\+.*|.*\\..*format\\(.*\\).*|.*%.*\\(.*\\).*|.*f'.*\\{.*\\}.*'.*")
    )
    or
    exists(DataFlow::AssignmentNode assign |
      assign.getLeft().getName().regexpMatch(".*QUERY.*") and
      assign.getRight().getValue().regexpMatch(".*\\+.*|.*\\..*format\\(.*\\).*|.*%.*\\(.*\\).*|.*f'.*\\{.*\\}.*'.*")
    )
  }
}

class SqlSink extends DataFlow::Node {
  SqlSink() {
    exists(FunctionCall call |
      call.getTarget().hasQualifiedName("pg8000", "Connection", "run") or
      call.getTarget().hasQualifiedName("pg8000", "Connection", "execute") or
      call.getTarget().hasQualifiedName("pg8000", "Connection", "executemany") or
      call.getTarget().hasQualifiedName("pg8000", "Connection", "prepare") and
      call.getArgument(1).getType() != "string"
    )
  }
}

class SqlSanitizer extends DataFlow::Node {
  SqlSanitizer() {
    exists(FunctionCall call |
      call.getTarget().hasQualifiedName("pg8000", "Connection", "run") or
      call.getTarget().hasQualifiedName("pg8000", "Connection", "execute") or
      call.getTarget().hasQualifiedName("pg8000", "Connection", "executemany") or
      call.getTarget().hasQualifiedName("pg8000", "Connection", "prepare") and
      call.getArgument(1).getType() = "string" and
      call.getArgument(1).getValue().regexpMatch("^[^+%{}]*$")
    )
  }
}

class Config extends DataFlow::Configuration {
  Config() { this = "pg8000_sqli_config" }

  override predicate isSource(DataFlow::Node source) { source instanceof SqlSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) { sanitizer instanceof SqlSanitizer }

  override predicate propagates(DataFlow::Node pred, DataFlow::Node succ) {
    pred.getValue().regexpMatch(".*\\+.*|.*\\..*format\\(.*\\).*|.*%.*\\(.*\\).*|.*f'.*\\{.*\\}.*'.*")
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, Config config
where config.hasFlowPath(source, sink)
select sink, "Potential SQL injection vulnerability due to string concatenation with user input", 
  source, "User input flows here"