/**
 * @name aiopg-sqli
 * @description Detected string concatenation with a non-literal variable in an aiopg Python SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries instead.
 * @kind path-problem
 * @problem.severity warning
 * @id python/aiopg-sqli
 * @tags security
 *       cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
 *       technology: aiopg
 *       owasp: "A01:2017 - Injection"
 *       owasp: "A03:2021 - Injection"
 */

import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class NonLiteralSource extends DataFlow::Node {
  NonLiteralSource() {
    exists(DataFlow::AssignmentNode assign |
      assign.getRight().getText().regexpMatch(".+\\+.+") or
      assign.getRight().getText().regexpMatch(".+\\+=.+") or
      assign.getRight().getText().regexpMatch(".format\\(.+\\)") or
      assign.getRight().getText().regexpMatch(".%\\\(.+\\)") or
      assign.getRight().getText().regexpMatch("f'.+\\\{.+\\}.*'")
    |
      this.asDef() = assign.asDef()
    ) and
    exists(ControlFlow::Node ctx |
      ctx.getText().regexpMatch("async with \\$POOL.acquire\\(\\) as \\$CONN:") and
      ctx.getText().regexpMatch("async with \\$CONN.cursor\\(\\) as \\$CUR:")
    )
  }
}

class AiopgSink extends DataFlow::Node {
  AiopgSink() {
    exists(CallNode call |
      call.getMethodName().regexpMatch(".*execute.*") and
      exists(ControlFlow::Node ctx |
        ctx.getText().regexpMatch("async with \\$POOL.acquire\\(\\) as \\$CONN:") and
        ctx.getText().regexpMatch("async with \\$CONN.cursor\\(\\) as \\$CUR:")
      )
    |
      this.asExpr() = call.getArg(0)
    )
  }
}

class ParameterizedQuerySanitizer extends DataFlow::Node {
  ParameterizedQuerySanitizer() {
    exists(CallNode call |
      call.getMethodName().regexpMatch(".*execute.*") and
      call.getArg(0).getText().regexpMatch("^SELECT %s|^INSERT %s|^UPDATE %s|^DELETE %s") and
      call.getArg(1) != None()
    |
      this.asExpr() = call.getArg(0)
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "aiopg-sqli" }

  override predicate isSource(DataFlow::Node source) { source instanceof NonLiteralSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof AiopgSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof ParameterizedQuerySanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(MethodCall mc |
      (mc.getMethodName().regexpMatch(".*format.*|.*%s.*") or
       mc.getMethodName().regexpMatch("f'.+\\\{.+\\}.*'")) and
      pred.asExpr() = mc.getAnArgument() and
      succ.asExpr() = mc
    )
  }
}

from Config cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential SQL injection vulnerability due to string concatenation in aiopg SQL query. Use parameterized queries instead."