/**
 * @name Dangerous Groovy Shell Usage
 * @description A expression is built with a dynamic value. The source of the value(s) 
 *   should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind problem
 * @id java/dangerous-groovy-shell
 * @severity Warning
 * @tags security
 *       cwe/CWE-94
 *       owasp/a03
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

class GroovyShellSource extends DataFlow::Node {
  GroovyShellSource() {
    (
      exists(LocalVariable lv | 
        lv = this.asDefiningArgument() and
        (
          lv.getType().hasQualifiedName("groovy.lang", "GroovyShell") or
          lv.getType().hasQualifiedName("groovy.lang", "GroovyClassLoader")
        )
      )
    )
  }
}

class DangerousEvaluationSink extends DataFlow::Node {
  DangerousEvaluationSink() {
    exists(MethodAccess ma |
      ma = this.asExpr() and
      (
        ma.getMethod().getName() = "parse" or
        ma.getMethod().getName() = "evaluate" or
        ma.getMethod().getName() = "parseClass"
      ) and
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("groovy.lang", "GroovyShell") or
        ma.getMethod().getDeclaringType().hasQualifiedName("groovy.lang", "GroovyClassLoader")
      ) and
      this = ma.getArgument(0)
    )
  }
}

class GroovyShellLiteralSanitizer extends DataFlow::Node {
  GroovyShellLiteralSanitizer() {
    exists(Literal l |
      l = this.asExpr() and
      l.getType().hasQualifiedName("java.lang", "String")
    )
  }
}

class FixedStringSanitizer extends DataFlow::Node {
  FixedStringSanitizer() {
    exists(MethodAccess ma |
      ma = this.asExpr() and
      (
        ma.getMethod().getName() = "parse" or
        ma.getMethod().getName() = "evaluate" or
        ma.getMethod().getName() = "parseClass"
      ) and
      exists(Literal lit |
        lit = ma.getArgument(0).asExpr() and
        lit.getStringValue() = "..."
      )
    )
  }
}

class GroovyShellTaintTrackingConfig extends TaintTracking::Configuration {
  GroovyShellTaintTrackingConfig() { this = "GroovyShellTaintTrackingConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof GroovyShellSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof DangerousEvaluationSink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof GroovyShellLiteralSanitizer or
    sanitizer instanceof FixedStringSanitizer
  }
}

from DataFlow::Node source, DataFlow::Node sink
where
  any(GroovyShellTaintTrackingConfig config).hasFlow(source, sink)
select sink, "A expression is built with a dynamic value. The source of the value(s) should be verified."