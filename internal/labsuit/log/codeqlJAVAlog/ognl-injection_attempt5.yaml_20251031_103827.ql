/**
 * @name OGNL Injection
 * @description A expression is built with a dynamic value. The source of the value(s) should 
 *              be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id java/ognl-injection
 * @tags security
 *       cwe: "CWE-94: Improper Control of Generation of Code ('Code Injection')"
 *       owasp: "A03:2021 - Injection"
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.PathGraph

class OgnlConfig extends TaintTracking::Configuration {
  OgnlConfig() { this = "OGNL Injection Config" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      source.asParameter() = p and
      p.getValue().toString() != ""
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().getPackage().matches("ognl") and
      (
        ma.getMethod().getName() = "getGetMethod" or
        ma.getMethod().getName() = "getSetMethod" or
        ma.getMethod().getName() = "getField" or
        ma.getMethod().getName() = "setProperties" or
        ma.getMethod().getName() = "setProperty" or
        ma.getMethod().getName() = "getValue" or
        ma.getMethod().getName() = "setValue" or
        ma.getMethod().getName() = "translateVariables" or
        ma.getMethod().getName() = "translateVariablesCollection" or
        ma.getMethod().getName() = "shallBeIncluded" or
        ma.getMethod().getName() = "commaDelimitedStringToSet" or
        ma.getMethod().getName() = "evaluate" or
        ma.getMethod().getName() = "callMethod" or
        ma.getMethod().getName() = "compile" or
        ma.getMethod().getName() = "isTrue" or
        ma.getMethod().getName() = "findString" or
        ma.getMethod().getName() = "findValue" or
        ma.getMethod().getName() = "getText" or
        ma.getMethod().getName() = "makeSelectList" or
        ma.getMethod().getName() = "setParameter"
      ) and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists(StringLiteral sl |
      sanitizer.asExpr() = sl and
      sl.getValue().regexpMatch("^\"[^\"]*\"$")
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, OgnlConfig conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential OGNL injection from $@.", source.getNode(), 
"unverified user input"