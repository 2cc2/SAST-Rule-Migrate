/**
 * @name JPA SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection 
 * if variables in the SQL statement are not properly sanitized.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.8
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/a01
 *       external/owasp/a03
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.StringFormat
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.StringLiterals
import semmle.code.java.BinaryOperations
import semmle.code.java.Methods

class StringFormatSource extends DataFlow::Node {
  StringFormatSource() {
    exists(StringFormatExpr expr |
      expr.getFormatLiteral().getStringValue().matches("%s") and
      this.asExpr() = expr
    )
    or
    exists(BinaryAddition add |
      add.getLeftOperand().getType().hasName("String") and
      add.getRightOperand().getType().hasName("String") and
      this.asExpr() = add
    )
  }
}

class SqlParamSource extends DataFlow::Node {
  SqlParamSource() {
    exists(MethodParameter param |
      param.getType().hasName("String") and
      param.getName().matches("%sql%") and
      this.asParameter() = param
    )
  }
}

class JpaQuerySink extends DataFlow::Node {
  JpaQuerySink() {
    exists(MethodAccess ma |
      (ma.getMethod().getName().matches("createQuery") or
       ma.getMethod().getName().matches("createNativeQuery")) and
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence", "EntityManager") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class StringLiteralSanitizer extends DataFlow::Node {
  StringLiteralSanitizer() {
    exists(StringLiteral lit |
      lit.getStringValue().matches("^\"[^\"]*\"\\s*\\+\\s*\"[^\"]*\"$") and
      this.asExpr() = lit
    )
  }
}

class JpaSqlInjectionConfig extends TaintTracking::Configuration {
  JpaSqlInjectionConfig() { this = "JpaSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof StringFormatSource or
    source instanceof SqlParamSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof JpaQuerySink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof StringLiteralSanitizer
  }
}

from JpaSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables " +
  "in the SQL statement are not properly sanitized. Use prepared statements instead."