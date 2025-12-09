/**
 * @name JPA SQL Injection 
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized.
 * @id jpa-sqli
 * @kind problem
 * @severity warning
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */

import java
import DataFlow::PathGraph
import DataFlow::TaintTracking
import DataFlow::StringFormat
import DataFlow::DataFlow
import DataFlow::StringLiterals
import DataFlow::BinaryOperations
import DataFlow::Methods

class StringFormatSource extends DataFlow::Node {
  StringFormatSource() {
    exists(DataFlow::StringFormatExpr sfe |
      this = sfe.asDefiningNode()
    )
    or
    exists(DataFlow::BinaryAddition ba |
      this = ba.asDefiningNode() and
      ba.getLeftOperand().getType().hasName("String") and
      ba.getRightOperand().getType().hasName("String")
    )
  }
}

class SqlParamSource extends DataFlow::Node {
  SqlParamSource() {
    exists(DataFlow::ParameterNode p |
      this = p.asParameterNode() and
      p.getType().hasName("String") and
      p.getName().matches("%sql%")
    )
  }
}

class JpaQuerySink extends DataFlow::Node {
  JpaQuerySink() {
    exists(DataFlow::MethodCall mc |
      this = mc.asDefiningNode() and
      mc.getMethod().getName().matches("createQuery|createNativeQuery") and
      mc.getMethod().getDeclaringType().hasQualifiedName("javax.persistence", "EntityManager") and
      this = mc.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(DataFlow::StringLiteralNode sl |
      this = sl.asDefiningNode() and
      sl.getValue().matches("^\"[^\"]*\"\\s*\\+\\s*\"[^\"]*\"$")
    )
  }
}

class JpaSqlInjectionConfig extends TaintTracking::Configuration {
  JpaSqlInjectionConfig() { this = "JpaSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or source instanceof SqlParamSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof JpaQuerySink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof StringLiteralSanitizer
  }

  override predicate isSanitizer(DataFlow::Node node, DataFlow::Node sanitizedNode) {
    node instanceof StringLiteralSanitizer and node = sanitizedNode
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, JpaSqlInjectionConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'."