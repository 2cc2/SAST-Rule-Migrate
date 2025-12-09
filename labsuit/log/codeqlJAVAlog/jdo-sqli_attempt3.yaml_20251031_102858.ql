/**
 * @name JDO SQL Injection
 * @description Detected a formatted string in a SQL statement. This could lead to SQL injection.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id jdo-sqli
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.TaintTracking
import semmle.python.frameworks.jdo

class SQLFormatSource extends TaintTracking::Source {
  SQLFormatSource() {
    exists(FunctionCall fc |
      fc.getTarget().getName() = "format" and
      fc.getTarget().getQualifiedName().matches("String%") and
      this.asSource() = fc
    )
  }
}

class SQLConcatSource extends TaintTracking::Source {
  SQLConcatSource() {
    exists(BinaryExpr be |
      be.getOp() = "+" and
      be.getLeft().toString().matches("%SQL%") and
      be.getRight().toString().matches("%SQL%") and
      this.asSource() = be
    )
  }
}

class SQLParamSource extends TaintTracking::Source {
  SQLParamSource() {
    exists(Parameter p |
      p.getName().matches("%SQL%") and
      this.asSource() = p
    )
  }
}

class JDOQuerySink extends TaintTracking::Sink {
  JDOQuerySink() {
    exists(FunctionCall fc |
      (
        fc.getTarget().getName() = "setFilter" and
        fc.getTarget().getQualifiedName().matches("javax.jdo.Query%")
      ) or
      (
        fc.getTarget().getName() = "setGrouping" and
        fc.getTarget().getQualifiedName().matches("javax.jdo.Query%")
      ) or
      (
        fc.getTarget().getName() = "newQuery" and
        fc.getTarget().getQualifiedName().matches("javax.jdo.PersistenceManager%") and
        fc.getArgument(1) = this.asSink()
      ) and
      this.asSink() = fc.getArgument(0)
    )
  }
}

class SafeConcatSanitizer extends TaintTracking::Sanitizer {
  SafeConcatSanitizer() {
    exists(BinaryExpr be |
      be.getOp() = "+" and
      be.getLeft().toString().matches("\".*?\".*") and
      be.getRight().toString().matches("\".*?\".*") and
      this.asSanitizer() = be
    )
  }
}

class SafeParamSanitizer extends TaintTracking::Sanitizer {
  SafeParamSanitizer() {
    exists(Parameter p |
      p.getDefaultValue().toString().matches("\".*?\".*") and
      this.asSanitizer() = p
    )
  }
}

class JdoSqlTaintConfig extends TaintTracking::Configuration {
  JdoSqlTaintConfig() { this = "JdoSqlTaintConfig" }

  override predicate isSource(TaintTracking::Source source) {
    source instanceof SQLFormatSource or
    source instanceof SQLConcatSource or
    source instanceof SQLParamSource
  }

  override predicate isSink(TaintTracking::Sink sink) { sink instanceof JDOQuerySink }

  override predicate isSanitizer(TaintTracking::Sanitizer sanitizer) {
    sanitizer instanceof SafeConcatSanitizer or
    sanitizer instanceof SafeParamSanitizer
  }

  override predicate isAdditionalTaintStep(TaintTracking::TaintStep step) {
    exists(FunctionCall fc, Parameter p |
      step.fromSource(fc.getArgument(0)) and
      step.toSink(p) and
      p.getFunction() = fc.getTarget()
    )
  }
}

from JdoSqlTaintConfig cfg, TaintTracking::PathNode source, TaintTracking::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potentially unsafe SQL query construction from $@.",
  source.getNode(), "user input"