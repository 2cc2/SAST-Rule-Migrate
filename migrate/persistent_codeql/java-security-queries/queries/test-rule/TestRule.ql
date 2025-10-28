/**
 * @name OGNL Injection
 * @description A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.
 * @kind path-problem
 * @problem.severity warning
 * @id java/ognl-injection
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.ognl.Ognl

class OgnlConfiguration extends TaintTracking::Configuration {
  OgnlConfiguration() { this = "OgnlInjection" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p | source.asParameter() = p and p.getValue().toString() != "")
    or
    exists(LocalVariable v | source.asLocalVariable() = v and v.getInitializer().toString() != "")
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getGetMethod") 
      and ma.getMethod().getDeclaringType().hasQualifiedName("ognl", "OgnlReflectionProvider")
      and sink.asExpr() = ma.getArgument(1)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("getSetMethod") 
      and ma.getMethod().getDeclaringType().hasQualifiedName("ognl", "OgnlReflectionProvider")
      and sink.asExpr() = ma.getArgument(1)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("getField") 
      and ma.getMethod().getDeclaringType().hasQualifiedName("ognl", "OgnlReflectionProvider")
      and sink.asExpr() = ma.getArgument(1)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("setProperties") 
      and ma.getMethod().getDeclaringType().hasQualifiedName("ognl", "OgnlReflectionProvider")
      and sink.asExpr() = ma.getArgument(0)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("setProperty") 
      and ma.getMethod().getDeclaringType().hasQualifiedName("ognl", "OgnlReflectionProvider")
      and sink.asExpr() = ma.getArgument(0)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("getValue") 
      and ma.getMethod().getDeclaringType().hasQualifiedName("ognl", "OgnlReflectionProvider")
      and sink.asExpr() = ma.getArgument(0)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("setValue") 
      and ma.getMethod().getDeclaringType().hasQualifiedName("ognl", "OgnlReflectionProvider")
      and sink.asExpr() = ma.getArgument(0)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("translateVariables") 
      and ma.getMethod().getDeclaringType().hasQualifiedName("ognl", "TextParseUtil")
      and sink.asExpr() = ma.getArgument(0)
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("evaluate") 
      and ma.getMethod().getDeclaringType().hasQualifiedName("ognl", "OgnlUtil")
      and sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node.getType() instanceof Literal
  }

  override predicate isBarrier(DataFlow::Node node) {
    node.getBasicBlock().getASuccessor() instanceof ReturnStmt
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, OgnlConfiguration conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential OGNL Injection vulnerability detected"